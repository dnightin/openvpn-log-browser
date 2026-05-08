const http = require("node:http");
const https = require("node:https");
const fs = require("node:fs/promises");
const path = require("node:path");
const zlib = require("node:zlib");
const { promisify } = require("node:util");

const gunzip = promisify(zlib.gunzip);

const PORT = Number(process.env.PORT || 3000);
const BUCKET_URL = ensureTrailingSlash(process.env.S3_BUCKET_URL || "https://wc-openvpnlogs.s3.us-east-1.amazonaws.com/");
const LOG_PREFIX = process.env.LOG_PREFIX || "CloudConnexa/wellesley/";
const RAW_DIR = process.env.RAW_DIR || path.join(__dirname, "data", "raw");
const SECRET_KEY_RE = /(token|secret|password|credential|private.?key|client.?key|refresh|bearer|session)/i;

let store = {
  records: [],
  objects: [],
  source: "not loaded",
  loadedAt: null,
  error: null
};

function ensureTrailingSlash(value) {
  return value.endsWith("/") ? value : `${value}/`;
}

function httpGetBuffer(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith("https:") ? https : http;
    const req = client.get(url, { timeout: 30000 }, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        resolve(httpGetBuffer(new URL(res.headers.location, url).toString()));
        return;
      }
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        const body = Buffer.concat(chunks);
        if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`GET ${url} failed with ${res.statusCode}: ${body.toString("utf8", 0, 500)}`));
          return;
        }
        resolve(body);
      });
    });
    req.on("timeout", () => req.destroy(new Error(`GET ${url} timed out`)));
    req.on("error", reject);
  });
}

function parseS3List(xml) {
  const objects = [];
  const contentRe = /<Contents>([\s\S]*?)<\/Contents>/g;
  let match;
  while ((match = contentRe.exec(xml))) {
    const block = match[1];
    const key = xmlText(block, "Key");
    if (!key || !key.startsWith(LOG_PREFIX) || !key.endsWith(".jsonl.gz")) continue;
    objects.push({
      key,
      lastModified: xmlText(block, "LastModified"),
      size: Number(xmlText(block, "Size") || 0),
      etag: xmlText(block, "ETag").replaceAll("&quot;", "\"")
    });
  }
  return objects.sort((a, b) => a.key.localeCompare(b.key));
}

function xmlText(block, tag) {
  const match = block.match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`));
  return match ? decodeXml(match[1]) : "";
}

function decodeXml(value) {
  return value
    .replaceAll("&amp;", "&")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&apos;", "'")
    .replaceAll("&quot;", "\"");
}

async function listBucketObjects() {
  const xml = (await httpGetBuffer(BUCKET_URL)).toString("utf8");
  return parseS3List(xml);
}

async function walk(dir) {
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
  const files = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...await walk(full));
    if (entry.isFile()) files.push(full);
  }
  return files;
}

async function parseJsonlGz(compressed, sourceKey) {
  const text = (await gunzip(compressed)).toString("utf8");
  const out = [];
  for (const [lineIndex, line] of text.split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    try {
      const raw = JSON.parse(line);
      out.push(normalizeRecord(raw, sourceKey, lineIndex + 1));
    } catch (error) {
      out.push(normalizeRecord({ parseError: error.message, rawLine: line }, sourceKey, lineIndex + 1));
    }
  }
  return out;
}

function normalizeRecord(raw, sourceKey, lineNumber) {
  const log = raw.log && typeof raw.log === "object" ? raw.log : {};
  const fields = Array.isArray(log.fields) ? log.fields : [];
  const info = Array.isArray(log.additionalInfo) ? log.additionalInfo : [];
  const timestamp = raw.timestamp || "";
  const eventName = raw.eventName || "";
  const userName = raw.parentEntityName || log.parentEntityName || raw.initiatorName || raw.initiator || "";
  const deviceName = raw.initiatorType === "Device" ? raw.initiatorName : log.entityName || raw.initiatorName || "";
  const publicIp = raw.publicIp || raw.initiatorPublicIp || log.clientPublicIp || "";
  const operation = log.operation || eventName || "";
  const entityType = log.entityType || raw.initiatorType || "";
  const entityName = log.entityName || deviceName || "";
  const os = [log.clientOsType, log.clientOsVersion].filter(Boolean).join(" ");
  const tunnelIp = [log.clientTunnelIpV4, log.clientTunnelIpV6].filter(Boolean).join(" / ");
  const gateway = [log.gatewayRegionName, log.gatewayId].filter(Boolean).join(" / ");
  const bytesIn = Number(log.sessionBytesIn || 0);
  const bytesOut = Number(log.sessionBytesOut || 0);
  const fieldText = fields.map((field) => `${field.name || ""}:${field.oldValue || ""}->${field.newValue || ""}`).join(" ");
  const infoText = info.map((item) => `${item.name || ""}:${item.value || ""}`).join(" ");
  const searchText = [
    timestamp,
    raw.category,
    eventName,
    raw.initiator,
    raw.initiatorName,
    userName,
    deviceName,
    raw.initiatorType,
    publicIp,
    raw.cloudId,
    operation,
    entityType,
    entityName,
    log.entityId,
    raw.parentEntityName,
    log.parentEntityName,
    log.clientSessionId,
    log.clientUUID,
    tunnelIp,
    gateway,
    os,
    log.sessionProtocol,
    log.sessionDisconnectReason,
    fieldText,
    infoText,
    raw.traceId,
    raw.userAgent,
    JSON.stringify(raw)
  ].filter(Boolean).join(" ").toLowerCase();

  return {
    id: `${sourceKey}:${lineNumber}`,
    sourceKey,
    lineNumber,
    timestamp,
    date: timestamp ? timestamp.slice(0, 10) : "",
    category: raw.category || "",
    eventName,
    initiator: raw.initiator || "",
    initiatorName: raw.initiatorName || raw.initiator || "",
    userName,
    deviceName,
    initiatorType: raw.initiatorType || "",
    publicIp,
    operation,
    entityType,
    entityName,
    parentEntityName: raw.parentEntityName || log.parentEntityName || "",
    sessionId: log.clientSessionId || "",
    protocol: log.sessionProtocol || "",
    gateway,
    gatewayRegion: log.gatewayRegion || "",
    os,
    tunnelIp,
    tunnelIpV4: log.clientTunnelIpV4 || "",
    tunnelIpV6: log.clientTunnelIpV6 || "",
    sessionStartTime: log.sessionStartTime || "",
    sessionEndTime: log.sessionEndTime || "",
    durationSeconds: Number(log.sessionDurationSeconds || 0),
    bytesIn,
    bytesOut,
    disconnectReason: log.sessionDisconnectReason || "",
    traceId: raw.traceId || "",
    userAgent: raw.userAgent || raw.initiatorClientAgent || "",
    raw,
    searchText
  };
}

async function parseObject(compressed, key) {
  return parseJsonlGz(compressed, key);
}

async function loadFromS3() {
  const objects = await listBucketObjects();
  const records = [];
  for (const object of objects) {
    const url = BUCKET_URL + object.key.split("/").map(encodeURIComponent).join("/");
    const compressed = await httpGetBuffer(url);
    records.push(...await parseObject(compressed, object.key));
  }
  return { records, objects, source: BUCKET_URL };
}

async function loadFromRawDir() {
  const files = await walk(RAW_DIR);
  const gzFiles = files.filter((file) => file.endsWith(".jsonl.gz")).sort();
  const records = [];
  for (const file of gzFiles) {
    const compressed = await fs.readFile(file);
    const key = path.relative(RAW_DIR, file).replaceAll(path.sep, "/");
    records.push(...await parseObject(compressed, key));
  }
  return {
    records,
    objects: gzFiles.map((file) => ({ key: path.relative(RAW_DIR, file).replaceAll(path.sep, "/"), size: 0, lastModified: "" })),
    source: RAW_DIR
  };
}

async function refresh() {
  store = { ...store, error: null };
  try {
    store = { ...await loadFromS3(), loadedAt: new Date().toISOString(), error: null };
  } catch (s3Error) {
    const s3Message = s3Error.message || "access denied or network blocked";
    try {
      const local = await loadFromRawDir();
      store = {
        ...local,
        loadedAt: new Date().toISOString(),
        error: `S3 unavailable (${s3Message}); loaded local cache instead.`
      };
    } catch (localError) {
      store = {
        records: [],
        objects: [],
        source: "none",
        loadedAt: new Date().toISOString(),
        error: `S3 unavailable (${s3Message}); local cache unavailable (${localError.message}).`
      };
    }
  }
}

function filterRecords(params) {
  const q = (params.get("q") || "").trim().toLowerCase();
  const category = params.get("category") || "";
  const eventName = params.get("eventName") || "";
  const os = params.get("os") || "";
  const gateway = params.get("gateway") || "";
  const start = params.get("start") || "";
  const end = params.get("end") || "";
  const limit = Math.min(Number(params.get("limit") || 200), 1000);

  const rows = store.records
    .filter((record) => !q || record.searchText.includes(q))
    .filter((record) => !category || record.category === category)
    .filter((record) => !eventName || record.eventName === eventName)
    .filter((record) => !os || record.os.startsWith(os))
    .filter((record) => !gateway || record.gateway.includes(gateway))
    .filter((record) => !start || record.timestamp >= start)
    .filter((record) => !end || record.timestamp <= end)
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp));

  return { total: rows.length, rows: rows.slice(0, limit) };
}

function facets() {
  return {
    categories: unique(store.records.map((record) => record.category)),
    eventNames: unique(store.records.map((record) => record.eventName)),
    operatingSystems: unique(store.records.map((record) => record.os.split(" ")[0])),
    gateways: unique(store.records.map((record) => record.gateway)),
    users: unique(store.records.map((record) => record.userName)).slice(0, 25),
    ips: unique(store.records.map((record) => record.publicIp)).slice(0, 25)
  };
}

function unique(values) {
  return [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b));
}

function redact(value, key = "") {
  if (SECRET_KEY_RE.test(key)) return "[redacted]";
  if (Array.isArray(value)) return value.map((item) => redact(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => [childKey, redact(childValue, childKey)]));
  }
  return value;
}

function stats() {
  const timestamps = store.records.map((record) => record.timestamp).filter(Boolean).sort();
  const byDay = {};
  const byEvent = {};
  const sessionLatest = new Map();
  let totalBytesIn = 0;
  let totalBytesOut = 0;
  for (const record of store.records) {
    if (!record.date) continue;
    byDay[record.date] = (byDay[record.date] || 0) + 1;
    if (record.eventName) byEvent[record.eventName] = (byEvent[record.eventName] || 0) + 1;
    totalBytesIn += record.bytesIn || 0;
    totalBytesOut += record.bytesOut || 0;
    if (record.sessionId) {
      const current = sessionLatest.get(record.sessionId);
      if (!current || record.timestamp > current.timestamp) sessionLatest.set(record.sessionId, record);
    }
  }
  const activeSessions = [...sessionLatest.values()].filter((record) => record.eventName === "client-connected").length;
  return {
    records: store.records.length,
    objects: store.objects.length,
    activeSessions,
    byEvent,
    totalBytesIn,
    totalBytesOut,
    source: store.source,
    loadedAt: store.loadedAt,
    error: store.error,
    firstTimestamp: timestamps[0] || "",
    lastTimestamp: timestamps[timestamps.length - 1] || "",
    byDay
  };
}

function json(res, data, status = 200) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
  res.end(body);
}

function html(res) {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(INDEX_HTML);
}

function notFound(res) {
  json(res, { error: "Not found" }, 404);
}

async function handler(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    if (url.pathname === "/") return html(res);
    if (url.pathname === "/api/stats") return json(res, stats());
    if (url.pathname === "/api/facets") return json(res, facets());
    if (url.pathname === "/api/search") {
      const result = filterRecords(url.searchParams);
      return json(res, {
        ...result,
        rows: result.rows.map(({ searchText, raw, ...record }) => record)
      });
    }
    if (url.pathname === "/api/record") {
      const id = url.searchParams.get("id");
      const record = store.records.find((item) => item.id === id);
      if (!record) return notFound(res);
      return json(res, { ...record, searchText: undefined, raw: redact(record.raw) });
    }
    if (url.pathname === "/api/reload" && req.method === "POST") {
      await refresh();
      return json(res, stats());
    }
    return notFound(res);
  } catch (error) {
    json(res, { error: error.message }, 500);
  }
}

const INDEX_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenVPN Log Search</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8fb;
      --panel: #ffffff;
      --text: #18202b;
      --muted: #667085;
      --line: #d9dee8;
      --accent: #166c7d;
      --accent-2: #8a5b16;
      --danger: #9f2936;
      --chip: #eef4f6;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--text); }
    header { background: #111827; color: white; padding: 18px 24px; }
    header h1 { margin: 0; font-size: 22px; font-weight: 720; letter-spacing: 0; }
    header .sub { margin-top: 4px; color: #cbd5e1; font-size: 13px; }
    main { padding: 18px 24px 28px; max-width: 1500px; margin: 0 auto; }
    .stats { display: grid; grid-template-columns: repeat(5, minmax(150px, 1fr)); gap: 10px; margin-bottom: 14px; }
    .stat { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 12px; min-width: 0; }
    .stat strong { display: block; font-size: 20px; }
    .stat span { color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
    .toolbar { display: grid; grid-template-columns: minmax(260px, 1fr) 160px 170px 150px 190px 150px 150px auto; gap: 8px; align-items: end; margin-bottom: 14px; }
    label { display: grid; gap: 5px; color: var(--muted); font-size: 12px; font-weight: 650; }
    input, select, button { height: 38px; border-radius: 7px; border: 1px solid var(--line); background: white; color: var(--text); padding: 0 10px; font: inherit; min-width: 0; }
    button { background: var(--accent); color: white; border-color: var(--accent); cursor: pointer; font-weight: 700; }
    button.secondary { background: white; color: var(--accent); }
    .status { margin: 6px 0 12px; color: var(--muted); font-size: 13px; }
    .status.error { color: var(--danger); }
    .muted { color: var(--muted); font-size: 12px; }
    .layout { display: grid; grid-template-columns: minmax(0, 1fr) 420px; gap: 14px; align-items: start; }
    table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
    th, td { padding: 9px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 13px; }
    th { color: var(--muted); background: #f1f5f9; font-size: 12px; position: sticky; top: 0; z-index: 1; }
    tr { cursor: pointer; }
    tr:hover td { background: #f8fbfc; }
    td.time { white-space: nowrap; font-variant-numeric: tabular-nums; }
    td.ip, td.user, td.op { overflow-wrap: anywhere; }
    .chip { display: inline-flex; align-items: center; min-height: 23px; padding: 2px 8px; border-radius: 999px; background: var(--chip); color: #28505a; font-size: 12px; font-weight: 650; }
    aside { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; min-height: 360px; position: sticky; top: 12px; }
    aside h2 { margin: 0; padding: 13px 14px; font-size: 15px; }
    .detail-head { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--line); }
    .icon-button { width: 32px; height: 32px; margin-right: 8px; padding: 0; border-radius: 7px; border: 1px solid transparent; background: transparent; color: var(--muted); font-size: 22px; line-height: 1; display: none; align-items: center; justify-content: center; }
    .icon-button:hover { border-color: var(--line); background: #f8fafc; color: var(--text); }
    .details { padding: 12px 14px; }
    .kv { display: grid; grid-template-columns: 120px minmax(0, 1fr); gap: 6px 10px; font-size: 13px; margin-bottom: 12px; }
    .kv div:nth-child(odd) { color: var(--muted); }
    pre { margin: 0; padding: 12px; background: #0f172a; color: #dbeafe; border-radius: 8px; overflow: auto; max-height: 520px; font-size: 12px; line-height: 1.45; }
    .bars { display: flex; gap: 2px; align-items: end; height: 34px; margin-top: 8px; }
    .bar { background: var(--accent-2); min-width: 3px; flex: 1; border-radius: 2px 2px 0 0; opacity: .8; }
    @media (max-width: 1100px) {
      .toolbar { grid-template-columns: 1fr 1fr; }
      .layout { grid-template-columns: 1fr; }
      aside { position: static; }
      .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 700px) {
      main, header { padding-left: 12px; padding-right: 12px; }
      .toolbar { grid-template-columns: 1fr; }
      .stats { grid-template-columns: 1fr; }
      th:nth-child(4), td:nth-child(4), th:nth-child(6), td:nth-child(6), th:nth-child(7), td:nth-child(7) { display: none; }
    }
  </style>
</head>
<body>
  <header>
    <h1>OpenVPN Log Search</h1>
    <div class="sub" id="sourceLine">Loading authorized CloudConnexa audit logs...</div>
  </header>
  <main>
    <section class="stats" id="stats"></section>
    <form class="toolbar" id="filters">
      <label>Search
        <input name="q" autocomplete="off" placeholder="user, IP, operation, device, trace id">
      </label>
      <label>Category
        <select name="category"><option value="">All</option></select>
      </label>
      <label>Event
        <select name="eventName"><option value="">All</option></select>
      </label>
      <label>OS
        <select name="os"><option value="">All</option></select>
      </label>
      <label>Gateway
        <select name="gateway"><option value="">All</option></select>
      </label>
      <label>Start
        <input name="start" placeholder="2026-05-01">
      </label>
      <label>End
        <input name="end" placeholder="2026-05-09">
      </label>
      <button type="button" class="secondary" id="reload">Reload</button>
    </form>
    <div class="status" id="status"></div>
    <section class="layout">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>User</th>
            <th>Event</th>
            <th>Device</th>
            <th>IP / Tunnel</th>
            <th>Gateway</th>
            <th>Duration</th>
            <th>Transfer</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
      <aside>
        <div class="detail-head">
          <h2>Event Detail</h2>
          <button type="button" class="icon-button" id="closeDetail" title="Close event detail" aria-label="Close event detail">&times;</button>
        </div>
        <div class="details" id="details">Select a log event.</div>
      </aside>
    </section>
  </main>
  <script>
    const filters = document.querySelector("#filters");
    const rows = document.querySelector("#rows");
    const statusEl = document.querySelector("#status");
    const details = document.querySelector("#details");
    const statsEl = document.querySelector("#stats");
    const sourceLine = document.querySelector("#sourceLine");
    const closeDetail = document.querySelector("#closeDetail");
    const IDLE_RELOAD_MS = 30 * 60 * 1000;
    let idleReloadTimer;

    async function getJson(url, options) {
      const res = await fetch(url, options);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      return data;
    }

    function esc(value) {
      return String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
    }

    function params() {
      const form = new FormData(filters);
      const out = new URLSearchParams();
      for (const [key, value] of form.entries()) if (String(value).trim()) out.set(key, String(value).trim());
      out.set("limit", "300");
      return out;
    }

    async function loadFacets() {
      const data = await getJson("/api/facets");
      fill("category", data.categories);
      fill("eventName", data.eventNames);
      fill("os", data.operatingSystems);
      fill("gateway", data.gateways);
    }

    function fill(name, values) {
      const select = filters.elements[name];
      const current = select.value;
      select.innerHTML = '<option value="">All</option>' + values.map(value => '<option>' + esc(value) + '</option>').join("");
      select.value = current;
    }

    async function loadStats() {
      const data = await getJson("/api/stats");
      sourceLine.textContent = data.source + " | loaded " + (data.loadedAt || "never");
      statusEl.textContent = data.error || "";
      statusEl.className = data.error ? "status error" : "status";
      const days = Object.entries(data.byDay || {});
      const max = Math.max(1, ...days.map(([, count]) => count));
      statsEl.innerHTML = [
        stat("Records", data.records),
        stat("Objects", data.objects),
        stat("Active sessions", data.activeSessions),
        stat("Disconnected", (data.byEvent && data.byEvent["client-disconnected"]) || 0),
        stat("Transfer", formatBytes((data.totalBytesIn || 0) + (data.totalBytesOut || 0))),
        '<div class="stat"><strong>' + days.length + '</strong><span>active days</span><div class="bars">' + days.map(([day, count]) => '<div class="bar" title="' + esc(day + ": " + count) + '" style="height:' + Math.max(5, Math.round((count / max) * 34)) + 'px"></div>').join("") + '</div></div>'
      ].join("");
    }

    function stat(label, value) {
      return '<div class="stat"><strong>' + esc(value) + '</strong><span>' + esc(label) + '</span></div>';
    }

    async function search() {
      const data = await getJson("/api/search?" + params());
      statusEl.textContent = (statusEl.className.includes("error") ? statusEl.textContent + " | " : "") + data.total + " matching events, showing " + data.rows.length;
      rows.innerHTML = data.rows.map(record => '<tr data-id="' + esc(record.id) + '">' +
        '<td class="time">' + esc(record.timestamp.replace("T", " ").replace("Z", "")) + '</td>' +
        '<td class="user">' + esc(record.userName || record.initiatorName) + '</td>' +
        '<td><span class="chip">' + esc(record.eventName || record.operation || "event") + '</span></td>' +
        '<td>' + esc(record.deviceName || record.entityName) + '<br><span class="muted">' + esc(record.os) + '</span></td>' +
        '<td class="ip">' + esc(record.publicIp) + '<br><span class="muted">' + esc(record.tunnelIp) + '</span></td>' +
        '<td>' + esc(record.gateway || record.gatewayRegion) + '<br><span class="muted">' + esc(record.protocol) + '</span></td>' +
        '<td>' + esc(formatDuration(record.durationSeconds)) + '</td>' +
        '<td>' + esc(formatBytes((record.bytesIn || 0) + (record.bytesOut || 0))) + '</td>' +
      '</tr>').join("");
    }

    async function selectRecord(id) {
      const record = await getJson("/api/record?id=" + encodeURIComponent(id));
      closeDetail.style.display = "inline-flex";
      details.innerHTML = '<div class="kv">' +
        kv("Timestamp", record.timestamp) +
        kv("Event", record.eventName || record.operation) +
        kv("User", record.userName || record.initiatorName) +
        kv("Device", record.deviceName || record.entityName) +
        kv("Public IP", record.publicIp) +
        kv("Tunnel IP", record.tunnelIp) +
        kv("Gateway", record.gateway) +
        kv("OS", record.os) +
        kv("Protocol", record.protocol) +
        kv("Session ID", record.sessionId) +
        kv("Duration", formatDuration(record.durationSeconds)) +
        kv("Transfer", formatBytes((record.bytesIn || 0) + (record.bytesOut || 0))) +
        kv("Disconnect", record.disconnectReason) +
        kv("Trace ID", record.traceId) +
        kv("Source", record.sourceKey + ":" + record.lineNumber) +
      '</div><pre>' + esc(JSON.stringify(record.raw, null, 2)) + '</pre>';
    }

    function kv(key, value) {
      return '<div>' + esc(key) + '</div><div>' + esc(value || "-") + '</div>';
    }

    closeDetail.addEventListener("click", () => {
      closeDetail.style.display = "none";
      details.textContent = "Select a log event.";
    });

    function resetIdleReloadTimer() {
      clearTimeout(idleReloadTimer);
      idleReloadTimer = setTimeout(async () => {
        statusEl.textContent = "Idle refresh...";
        try {
          await getJson("/api/reload", { method: "POST" });
          await boot();
        } catch (error) {
          showError(error);
        } finally {
          resetIdleReloadTimer();
        }
      }, IDLE_RELOAD_MS);
    }

    ["click", "keydown", "mousemove", "scroll", "touchstart"].forEach(eventName => {
      window.addEventListener(eventName, resetIdleReloadTimer, { passive: true });
    });

    function formatDuration(seconds) {
      seconds = Number(seconds || 0);
      if (!seconds) return "-";
      const h = Math.floor(seconds / 3600);
      const m = Math.floor((seconds % 3600) / 60);
      const s = seconds % 60;
      if (h) return h + "h " + m + "m";
      if (m) return m + "m " + s + "s";
      return s + "s";
    }

    function formatBytes(bytes) {
      bytes = Number(bytes || 0);
      if (!bytes) return "-";
      const units = ["B", "KB", "MB", "GB", "TB"];
      let value = bytes;
      let unit = 0;
      while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit += 1;
      }
      return (value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)) + " " + units[unit];
    }

    filters.addEventListener("input", () => search().catch(showError));
    filters.addEventListener("change", () => search().catch(showError));
    rows.addEventListener("click", event => {
      const tr = event.target.closest("tr");
      if (tr) selectRecord(tr.dataset.id).catch(showError);
    });
    document.querySelector("#reload").addEventListener("click", async () => {
      statusEl.textContent = "Reloading...";
      await getJson("/api/reload", { method: "POST" });
      await boot();
    });

    function showError(error) {
      statusEl.textContent = error.message;
      statusEl.className = "status error";
    }

    async function boot() {
      await loadStats();
      await loadFacets();
      await search();
      resetIdleReloadTimer();
    }

    boot().catch(showError);
  </script>
</body>
</html>`;

if (process.argv.includes("--ingest")) {
  refresh().then(() => {
    console.log(JSON.stringify(stats(), null, 2));
  }).catch((error) => {
    console.error(error);
    process.exit(1);
  });
} else {
  refresh().then(() => {
    http.createServer(handler).listen(PORT, () => {
      console.log(`OpenVPN Log Search listening on http://localhost:${PORT}`);
      if (store.error) console.warn(store.error);
    });
  }).catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
