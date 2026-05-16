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
const FETCH_CONCURRENCY = Math.max(1, Number(process.env.FETCH_CONCURRENCY || 25));
const AUTO_REFRESH_MINUTES = Math.max(0, Number(process.env.AUTO_REFRESH_MINUTES || 30));
const ACTIVE_SESSION_MAX_AGE_HOURS = Math.max(1, Number(process.env.ACTIVE_SESSION_MAX_AGE_HOURS || 72));
const MYSQL_ENABLED = Boolean(process.env.MYSQL_HOST || process.env.MYSQL_USER || process.env.MYSQL_DATABASE);
const MYSQL_CONFIG = {
  host: process.env.MYSQL_HOST || "127.0.0.1",
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER || "openvpn_log_browser",
  password: process.env.MYSQL_PASSWORD || "",
  database: process.env.MYSQL_DATABASE || "openvpn_log_browser"
};
const SECRET_KEY_RE = /(token|secret|password|credential|private.?key|client.?key|refresh|bearer|session)/i;

let store = {
  records: [],
  objects: [],
  source: "not loaded",
  loadedAt: null,
  error: "Loading logs..."
};
let refreshPromise = null;
let mysqlPool = null;
let mysqlStatus = MYSQL_ENABLED ? "not connected" : "disabled";

function ensureTrailingSlash(value) {
  return value.endsWith("/") ? value : `${value}/`;
}

async function httpGetBuffer(url, attempts = 3) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await httpGetBufferOnce(url);
    } catch (error) {
      lastError = error;
      if (attempt < attempts) await delay(500 * attempt);
    }
  }
  throw lastError;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function httpGetBufferOnce(url) {
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
  const objects = [];
  let marker = "";
  for (;;) {
    const pageUrl = marker ? `${BUCKET_URL}?marker=${encodeURIComponent(marker)}` : BUCKET_URL;
    const xml = (await httpGetBuffer(pageUrl)).toString("utf8");
    const pageObjects = parseS3List(xml);
    objects.push(...pageObjects);
    const isTruncated = xmlText(xml, "IsTruncated").toLowerCase() === "true";
    if (!isTruncated || pageObjects.length === 0) break;
    marker = pageObjects[pageObjects.length - 1].key;
  }
  return objects.sort((a, b) => a.key.localeCompare(b.key));
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
  const failed = [];
  for (let index = 0; index < objects.length; index += FETCH_CONCURRENCY) {
    const batch = objects.slice(index, index + FETCH_CONCURRENCY);
    const batchRecords = await Promise.all(batch.map(async (object) => {
      try {
        const url = BUCKET_URL + object.key.split("/").map(encodeURIComponent).join("/");
        const compressed = await httpGetBuffer(url);
        return parseObject(compressed, object.key);
      } catch (error) {
        failed.push(`${object.key}: ${error.message}`);
        return [];
      }
    }));
    for (const objectRecords of batchRecords) records.push(...objectRecords);
  }
  return {
    records,
    objects,
    source: BUCKET_URL,
    error: failed.length ? `Skipped ${failed.length} S3 object(s) after retries. First error: ${failed[0]}` : null
  };
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

async function initMysql() {
  if (!MYSQL_ENABLED) return;
  const mysql = require("mysql2/promise");
  mysqlPool = mysql.createPool({
    ...MYSQL_CONFIG,
    waitForConnections: true,
    connectionLimit: 4,
    enableKeepAlive: true,
    timezone: "Z"
  });
  await mysqlPool.query(`
    CREATE TABLE IF NOT EXISTS connected_user_counts (
      sampled_at DATETIME NOT NULL PRIMARY KEY,
      connected_users INT UNSIGNED NOT NULL,
      excluded_users INT UNSIGNED NOT NULL
    )
  `);
  mysqlStatus = "connected";
}

async function saveConnectedCountSample() {
  if (!mysqlPool || !store.records.length) return;
  try {
    const snapshot = connectedUsersSnapshot();
    const sampledAt = mysqlDate(new Date());
    await mysqlPool.execute(
      `INSERT INTO connected_user_counts (sampled_at, connected_users, excluded_users)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE connected_users = VALUES(connected_users), excluded_users = VALUES(excluded_users)`,
      [sampledAt, snapshot.connectedUsers, snapshot.excludedUsers]
    );
    await mysqlPool.execute("DELETE FROM connected_user_counts WHERE sampled_at < UTC_TIMESTAMP() - INTERVAL 365 DAY");
    mysqlStatus = "connected";
  } catch (error) {
    mysqlStatus = `unavailable: ${error.message}`;
    console.error(error);
  }
}

function mysqlDate(date) {
  return date.toISOString().slice(0, 19).replace("T", " ");
}

async function refresh() {
  if (refreshPromise) return refreshPromise;
  refreshPromise = refreshNow().finally(() => {
    refreshPromise = null;
  });
  return refreshPromise;
}

async function refreshNow() {
  store = { ...store, error: null };
  try {
    const loaded = await loadFromS3();
    store = { ...loaded, loadedAt: new Date().toISOString(), error: loaded.error || null };
    await saveConnectedCountSample();
  } catch (s3Error) {
    const s3Message = s3Error.message || "access denied or network blocked";
    try {
      const local = await loadFromRawDir();
      store = {
        ...local,
        loadedAt: new Date().toISOString(),
        error: `S3 unavailable (${s3Message}); loaded local cache instead.`
      };
      await saveConnectedCountSample();
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
  const limit = Math.min(Number(params.get("limit") || 1000), 10000);

  const rows = store.records
    .filter((record) => !q || record.searchText.includes(q))
    .filter((record) => !category || record.category === category)
    .filter((record) => !eventName || record.eventName === eventName)
    .filter((record) => !os || record.os.startsWith(os))
    .filter((record) => !gateway || record.gateway.includes(gateway))
    .filter((record) => !start || record.timestamp >= start)
    .filter((record) => !end || record.timestamp <= end)
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp));

  return { searched: store.records.length, total: rows.length, limit, rows: rows.slice(0, limit) };
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

function userChurnSummary(userName) {
  if (!userName) {
    return {
      userName: "",
      connected: 0,
      disconnected: 0,
      total: 0,
      shortSessions: 0,
      totalTransfer: 0,
      connectedForSeconds: 0,
      windowHours: 24,
      severity: "none",
      message: "No user identity on this event."
    };
  }

  const windowHours = 24;
  const timestamps = store.records.map((record) => Date.parse(record.timestamp)).filter(Number.isFinite);
  const newest = timestamps.length ? Math.max(...timestamps) : Date.now();
  const cutoff = newest - (windowHours * 60 * 60 * 1000);
  const userRecords = store.records.filter((record) => {
    if ((record.userName || record.parentEntityName || record.initiatorName) !== userName) return false;
    const ts = Date.parse(record.timestamp);
    return Number.isFinite(ts) && ts >= cutoff;
  });

  const connected = userRecords.filter((record) => record.eventName === "client-connected").length;
  const disconnected = userRecords.filter((record) => record.eventName === "client-disconnected").length;
  const shortSessions = userRecords.filter((record) => record.eventName === "client-disconnected" && record.durationSeconds > 0 && record.durationSeconds <= 60).length;
  const totalTransfer = userRecords.reduce((sum, record) => sum + (record.bytesIn || 0) + (record.bytesOut || 0), 0);
  const connectedForSeconds = connectedSecondsByUser(newest, cutoff).get(userName) || 0;
  const total = connected + disconnected;
  let severity = "normal";
  if (total >= 100 || shortSessions >= 25) severity = "high";
  else if (total >= 40 || shortSessions >= 10) severity = "elevated";

  const latest = userRecords
    .filter((record) => record.eventName === "client-connected" || record.eventName === "client-disconnected")
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    .slice(0, 8)
    .map((record) => ({
      timestamp: record.timestamp,
      eventName: record.eventName,
      deviceName: record.deviceName,
      publicIp: record.publicIp,
      gateway: record.gateway,
      durationSeconds: record.durationSeconds,
      disconnectReason: record.disconnectReason
    }));

  return {
    userName,
    connected,
    disconnected,
    total,
    shortSessions,
    totalTransfer,
    connectedForSeconds,
    windowHours,
    severity,
    message: churnMessage(severity, total, shortSessions, windowHours),
    latest
  };
}

function churnLeaderboard(limit = 10) {
  const windowHours = 24;
  const timestamps = store.records.map((record) => Date.parse(record.timestamp)).filter(Number.isFinite);
  const newest = timestamps.length ? Math.max(...timestamps) : Date.now();
  const cutoff = newest - (windowHours * 60 * 60 * 1000);
  const users = new Map();
  const connectedSeconds = connectedSecondsByUser(newest, cutoff);

  for (const record of store.records) {
    if (record.eventName !== "client-connected" && record.eventName !== "client-disconnected") continue;
    const ts = Date.parse(record.timestamp);
    if (!Number.isFinite(ts) || ts < cutoff) continue;
    const userName = record.userName || record.parentEntityName || record.initiatorName;
    if (!userName) continue;
    if (!users.has(userName)) {
      users.set(userName, {
        userName,
        connected: 0,
        disconnected: 0,
        shortSessions: 0,
        totalTransfer: 0,
        latestTimestamp: ""
      });
    }
    const user = users.get(userName);
    if (record.eventName === "client-connected") user.connected += 1;
    if (record.eventName === "client-disconnected") user.disconnected += 1;
    if (record.eventName === "client-disconnected" && record.durationSeconds > 0 && record.durationSeconds <= 60) user.shortSessions += 1;
    user.totalTransfer += (record.bytesIn || 0) + (record.bytesOut || 0);
    if (record.timestamp > user.latestTimestamp) user.latestTimestamp = record.timestamp;
  }

  const rows = [...users.values()].map((user) => {
    const total = user.connected + user.disconnected;
    user.connectedForSeconds = connectedSeconds.get(user.userName) || 0;
    let severity = "normal";
    if (total >= 100 || user.shortSessions >= 25) severity = "high";
    else if (total >= 40 || user.shortSessions >= 10) severity = "elevated";
    return {
      ...user,
      total,
      severity,
      message: churnMessage(severity, total, user.shortSessions, windowHours)
    };
  }).sort((a, b) => {
    const severityRank = { high: 2, elevated: 1, normal: 0 };
    return severityRank[b.severity] - severityRank[a.severity]
      || b.total - a.total
      || b.shortSessions - a.shortSessions
      || b.latestTimestamp.localeCompare(a.latestTimestamp);
  });

  return {
    windowHours,
    generatedAt: new Date(newest).toISOString(),
    excessiveCount: rows.filter((row) => row.severity === "high" || row.severity === "elevated").length,
    users: rows.slice(0, limit)
  };
}

function excessiveReconnectUsers(newest, cutoff) {
  const users = new Map();
  for (const record of store.records) {
    if (record.eventName !== "client-connected" && record.eventName !== "client-disconnected") continue;
    const ts = Date.parse(record.timestamp);
    if (!Number.isFinite(ts) || ts < cutoff) continue;
    const userName = record.userName || record.parentEntityName || record.initiatorName;
    if (!userName) continue;
    if (!users.has(userName)) users.set(userName, { total: 0, shortSessions: 0 });
    const user = users.get(userName);
    user.total += 1;
    if (record.eventName === "client-disconnected" && record.durationSeconds > 0 && record.durationSeconds <= 60) user.shortSessions += 1;
  }

  return new Set([...users.entries()]
    .filter(([, user]) => user.total >= 40 || user.shortSessions >= 10)
    .map(([userName]) => userName));
}

function connectionSessions() {
  const sessions = new Map();
  for (const record of store.records) {
    if (!record.sessionId || (record.eventName !== "client-connected" && record.eventName !== "client-disconnected")) continue;
    if (!sessions.has(record.sessionId)) {
      sessions.set(record.sessionId, {
        userName: record.userName || record.parentEntityName || record.initiatorName,
        start: Number.POSITIVE_INFINITY,
        end: null,
        latestTimestamp: ""
      });
    }
    const session = sessions.get(record.sessionId);
    if (!session.userName) session.userName = record.userName || record.parentEntityName || record.initiatorName;
    const start = Date.parse(record.sessionStartTime || record.timestamp);
    if (Number.isFinite(start)) session.start = Math.min(session.start, start);
    if (record.eventName === "client-disconnected") {
      const end = Date.parse(record.sessionEndTime || record.timestamp);
      if (Number.isFinite(end)) session.end = Math.max(session.end || 0, end);
    }
    if (record.timestamp > session.latestTimestamp) session.latestTimestamp = record.timestamp;
  }
  return [...sessions.values()].filter((session) => session.userName && Number.isFinite(session.start));
}

function connectedSecondsByUser(newest, cutoff) {
  const byUser = new Map();
  for (const session of connectionSessions()) {
    const end = session.end || newest;
    const overlapStart = Math.max(session.start, cutoff);
    const overlapEnd = Math.min(end, newest);
    const seconds = Math.max(0, Math.floor((overlapEnd - overlapStart) / 1000));
    byUser.set(session.userName, (byUser.get(session.userName) || 0) + seconds);
  }
  return byUser;
}

function connectedUsersSnapshot() {
  const timestamps = store.records.map((record) => Date.parse(record.timestamp)).filter(Number.isFinite);
  const newest = timestamps.length ? Math.max(...timestamps) : Date.now();
  const cutoff = newest - (24 * 60 * 60 * 1000);
  const staleCutoff = newest - (ACTIVE_SESSION_MAX_AGE_HOURS * 60 * 60 * 1000);
  const excludedUsers = excessiveReconnectUsers(newest, cutoff);
  const activeUsers = new Set();
  for (const session of connectionSessions()) {
    if (excludedUsers.has(session.userName)) continue;
    if (!session.end && session.start < staleCutoff) continue;
    const end = session.end || newest + 1;
    if (session.start <= newest && end > newest) activeUsers.add(session.userName);
  }
  return {
    connectedUsers: activeUsers.size,
    excludedUsers: excludedUsers.size,
    generatedAt: new Date(newest).toISOString()
  };
}

async function connectedUsersSeries(range = "week") {
  const normalizedRange = ["week", "month", "year"].includes(range) ? range : "week";
  if (mysqlPool) {
    try {
      return await connectedUsersSeriesFromMysql(normalizedRange);
    } catch (error) {
      mysqlStatus = `unavailable: ${error.message}`;
      console.error(error);
    }
  }
  return inMemoryConnectedUsersSeries(normalizedRange);
}

async function connectedUsersSeriesFromMysql(range) {
  const daysByRange = { week: 7, month: 31, year: 365 };
  const [rows] = await mysqlPool.execute(
    `SELECT sampled_at, connected_users, excluded_users
     FROM connected_user_counts
     WHERE sampled_at >= UTC_TIMESTAMP() - INTERVAL ? DAY
     ORDER BY sampled_at`,
    [daysByRange[range]]
  );
  return {
    range,
    source: "mysql",
    retentionDays: 365,
    mysqlStatus,
    points: rows.map((row) => ({
      timestamp: new Date(row.sampled_at).toISOString(),
      connectedUsers: Number(row.connected_users),
      excludedUsers: Number(row.excluded_users)
    }))
  };
}

function inMemoryConnectedUsersSeries(range = "week") {
  const rangeConfig = {
    week: { windowHours: 24 * 7, stepMinutes: 120 },
    month: { windowHours: 24 * 31, stepMinutes: 720 },
    year: { windowHours: 24 * 365, stepMinutes: 1440 }
  }[range] || { windowHours: 24 * 7, stepMinutes: 120 };
  const { windowHours, stepMinutes } = rangeConfig;
  const timestamps = store.records.map((record) => Date.parse(record.timestamp)).filter(Number.isFinite);
  const newest = timestamps.length ? Math.max(...timestamps) : Date.now();
  const start = newest - (windowHours * 60 * 60 * 1000);
  const stepMs = stepMinutes * 60 * 1000;
  const excludedUsers = excessiveReconnectUsers(newest, newest - (24 * 60 * 60 * 1000));
  const sessions = connectionSessions().filter((session) => !excludedUsers.has(session.userName));
  const points = [];

  for (let time = start; time <= newest; time += stepMs) {
    const activeUsers = new Set();
    for (const session of sessions) {
      if (!session.end && session.start < time - (ACTIVE_SESSION_MAX_AGE_HOURS * 60 * 60 * 1000)) continue;
      const end = session.end || newest + 1;
      if (session.start <= time && end > time) activeUsers.add(session.userName);
    }
    points.push({
      timestamp: new Date(time).toISOString(),
      connectedUsers: activeUsers.size
    });
  }

  if (!points.length || points[points.length - 1].timestamp !== new Date(newest).toISOString()) {
    const activeUsers = new Set();
    for (const session of sessions) {
      if (!session.end && session.start < newest - (ACTIVE_SESSION_MAX_AGE_HOURS * 60 * 60 * 1000)) continue;
      const end = session.end || newest + 1;
      if (session.start <= newest && end > newest) activeUsers.add(session.userName);
    }
    points.push({
      timestamp: new Date(newest).toISOString(),
      connectedUsers: activeUsers.size
    });
  }

  return {
    range,
    source: "memory",
    windowHours,
    stepMinutes,
    excludedUsers: excludedUsers.size,
    generatedAt: new Date(newest).toISOString(),
    points
  };
}

function churnMessage(severity, total, shortSessions, windowHours) {
  if (severity === "high") return `High reconnect activity: ${total} connect/disconnect events and ${shortSessions} short sessions in the last ${windowHours} hours.`;
  if (severity === "elevated") return `Elevated reconnect activity: ${total} connect/disconnect events and ${shortSessions} short sessions in the last ${windowHours} hours.`;
  return `No excessive reconnect pattern detected in the last ${windowHours} hours.`;
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
  let totalBytesIn = 0;
  let totalBytesOut = 0;
  for (const record of store.records) {
    if (!record.date) continue;
    byDay[record.date] = (byDay[record.date] || 0) + 1;
    if (record.eventName) byEvent[record.eventName] = (byEvent[record.eventName] || 0) + 1;
    totalBytesIn += record.bytesIn || 0;
    totalBytesOut += record.bytesOut || 0;
  }
  const newest = timestamps.length ? Date.parse(timestamps[timestamps.length - 1]) : Date.now();
  const staleCutoff = newest - (ACTIVE_SESSION_MAX_AGE_HOURS * 60 * 60 * 1000);
  const activeSessionRows = connectionSessions().filter((session) => {
    if (!session.end && session.start < staleCutoff) return false;
    const end = session.end || newest + 1;
    return session.start <= newest && end > newest;
  });
  const activeSessions = activeSessionRows.length;
  const activeUsers = unique(activeSessionRows.map((session) => session.userName)).length;
  return {
    records: store.records.length,
    objects: store.objects.length,
    activeSessions,
    activeUsers,
    mysql: mysqlStatus,
    byEvent,
    totalBytesIn,
    totalBytesOut,
    source: store.source,
    loadedAt: store.loadedAt,
    error: store.error,
    loading: Boolean(refreshPromise),
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
    if (url.pathname === "/api/churn") {
      const limit = Math.min(Number(url.searchParams.get("limit") || 10), 50);
      return json(res, churnLeaderboard(limit));
    }
    if (url.pathname === "/api/connected-users") return json(res, await connectedUsersSeries(url.searchParams.get("range") || "week"));
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
      return json(res, { ...record, searchText: undefined, raw: redact(record.raw), churn: userChurnSummary(record.userName || record.parentEntityName || record.initiatorName) });
    }
    if (url.pathname === "/api/reload" && req.method === "POST") {
      refresh().catch((error) => {
        store = { ...store, error: error.message };
        console.error(error);
      });
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
    body { margin: 0; background: var(--bg); color: var(--text); height: 100vh; overflow: hidden; }
    header { background: #111827; color: white; padding: 18px 24px; }
    header h1 { margin: 0; font-size: 22px; font-weight: 720; letter-spacing: 0; }
    header .sub { margin-top: 4px; color: #cbd5e1; font-size: 13px; }
    main { padding: 18px 24px 28px; max-width: 1500px; margin: 0 auto; height: calc(100vh - 65px); display: flex; flex-direction: column; min-height: 0; }
    .dashboard-top { display: grid; grid-template-columns: minmax(0, 1fr) 340px; gap: 10px; margin-bottom: 14px; align-items: stretch; }
    .stats { display: grid; grid-template-columns: repeat(5, minmax(150px, 1fr)); gap: 10px; min-width: 0; }
    .stat { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 12px; min-width: 0; }
    .stat strong { display: block; font-size: 20px; }
    .stat span { color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
    .chart-panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 10px; min-height: 126px; min-width: 0; }
    .chart-head { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; align-items: start; margin-bottom: 5px; }
    .chart-head h2 { margin: 0; font-size: 13px; line-height: 1.25; }
    .chart-head span { color: var(--muted); font-size: 11px; display: block; margin-top: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .chart-controls { display: grid; justify-items: end; gap: 3px; min-width: 0; }
    .chart-controls select { height: 28px; padding: 0 7px; font-size: 12px; }
    .chart { width: 100%; height: 82px; display: block; }
    .chart-grid { stroke: #e5e9f0; stroke-width: 1; }
    .chart-line { fill: none; stroke: var(--accent); stroke-width: 3; stroke-linecap: round; stroke-linejoin: round; }
    .chart-area { fill: rgba(22, 108, 125, .12); }
    .chart-dot { fill: var(--accent); }
    .chart-label { fill: var(--muted); font-size: 11px; }
    .toolbar { display: grid; grid-template-columns: minmax(260px, 1fr) 150px 160px 130px 170px 140px 140px 110px 150px; gap: 8px; align-items: end; margin-bottom: 14px; }
    label { display: grid; gap: 5px; color: var(--muted); font-size: 12px; font-weight: 650; }
    input, select, button { height: 38px; border-radius: 7px; border: 1px solid var(--line); background: white; color: var(--text); padding: 0 10px; font: inherit; min-width: 0; }
    button { background: var(--accent); color: white; border-color: var(--accent); cursor: pointer; font-weight: 700; }
    button.secondary { background: white; color: var(--accent); }
    .toolbar-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; align-self: end; }
    .toolbar-actions button { width: 100%; }
    .status { margin: 6px 0 12px; color: var(--muted); font-size: 13px; }
    .status.error { color: var(--danger); }
    .muted { color: var(--muted); font-size: 12px; }
    .layout { display: grid; grid-template-columns: minmax(0, 1fr) 420px; gap: 14px; align-items: stretch; min-height: 0; flex: 1; }
    .table-scroll { min-height: 0; overflow: auto; border: 1px solid var(--line); border-radius: 8px; background: var(--panel); }
    table { width: 100%; border-collapse: collapse; background: var(--panel); }
    th, td { padding: 9px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 13px; }
    th { color: var(--muted); background: #f1f5f9; font-size: 12px; position: sticky; top: 0; z-index: 1; }
    tr { cursor: pointer; }
    tr:hover td { background: #f8fbfc; }
    td.time { white-space: nowrap; font-variant-numeric: tabular-nums; }
    td.ip, td.user, td.op { overflow-wrap: anywhere; }
    .chip { display: inline-flex; align-items: center; min-height: 23px; padding: 2px 8px; border-radius: 999px; background: var(--chip); color: #28505a; font-size: 12px; font-weight: 650; }
    aside { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; min-height: 0; overflow: auto; }
    aside h2 { margin: 0; padding: 13px 14px; font-size: 15px; }
    .detail-head { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--line); }
    .icon-button { width: 32px; height: 32px; margin-right: 8px; padding: 0; border-radius: 7px; border: 1px solid transparent; background: transparent; color: var(--muted); font-size: 22px; line-height: 1; display: none; align-items: center; justify-content: center; }
    .icon-button:hover { border-color: var(--line); background: #f8fafc; color: var(--text); }
    .details { padding: 12px 14px; }
    .kv { display: grid; grid-template-columns: 120px minmax(0, 1fr); gap: 6px 10px; font-size: 13px; margin-bottom: 12px; }
    .kv div:nth-child(odd) { color: var(--muted); }
    .churn { border: 1px solid var(--line); border-radius: 8px; padding: 10px; margin-bottom: 12px; background: #fbfcfe; }
    .churn h3 { margin: 0 0 8px; font-size: 13px; }
    .churn .summary { margin-bottom: 8px; font-size: 13px; color: var(--muted); }
    .churn.elevated { border-color: #d99a2b; background: #fff8eb; }
    .churn.high { border-color: var(--danger); background: #fff1f2; }
    .mini-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 6px; margin-bottom: 8px; }
    .mini-stat { border: 1px solid var(--line); border-radius: 7px; padding: 7px; background: white; min-width: 0; }
    .mini-stat strong { display: block; font-size: 16px; }
    .mini-stat span { color: var(--muted); font-size: 11px; }
    .mini-list { display: grid; gap: 5px; font-size: 12px; color: var(--muted); }
    .mini-list div { overflow-wrap: anywhere; }
    .watch { border-bottom: 1px solid var(--line); padding: 12px 14px; }
    .watch-title { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; margin-bottom: 8px; }
    .watch-title h3 { margin: 0; font-size: 13px; }
    .watch-title span { color: var(--muted); font-size: 11px; }
    .watch-list { display: grid; gap: 8px; }
    .watch-user { border: 1px solid #9bc59f; border-left: 5px solid #2f8f46; border-radius: 8px; padding: 8px; background: #f1fbf4; }
    .watch-user.elevated { border-color: #d99a2b; background: #fff8eb; }
    .watch-user.high { border-color: var(--danger); background: #fff1f2; }
    .watch-user.elevated { border-left-color: #d99a2b; }
    .watch-user.high { border-left-color: var(--danger); }
    .watch-user strong { display: block; font-size: 13px; overflow-wrap: anywhere; }
    .watch-user span { color: var(--muted); display: block; font-size: 12px; margin-top: 3px; }
    pre { margin: 0; padding: 12px; background: #0f172a; color: #dbeafe; border-radius: 8px; overflow: auto; max-height: 520px; font-size: 12px; line-height: 1.45; }
    .bars { display: flex; gap: 2px; align-items: end; height: 34px; margin-top: 8px; }
    .bar { background: var(--accent-2); min-width: 3px; flex: 1; border-radius: 2px 2px 0 0; opacity: .8; }
    @media (max-width: 1100px) {
      .toolbar { grid-template-columns: 1fr 1fr; }
      .layout { grid-template-columns: 1fr; }
      aside { min-height: 420px; }
      .dashboard-top { grid-template-columns: 1fr; }
      .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 700px) {
      main, header { padding-left: 12px; padding-right: 12px; }
      .toolbar { grid-template-columns: 1fr; }
      body { overflow: auto; height: auto; }
      main { height: auto; }
      .stats { grid-template-columns: 1fr; }
      .chart-head { grid-template-columns: 1fr; }
      .chart-controls { justify-items: start; }
      .table-scroll { max-height: 65vh; }
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
    <section class="dashboard-top">
      <div class="stats" id="stats"></div>
      <aside class="chart-panel">
        <div class="chart-head">
          <h2>Connected Users Over Time</h2>
          <div class="chart-controls">
            <select id="connectedRange" aria-label="Connected users time range">
              <option value="week">Week</option>
              <option value="month">Month</option>
              <option value="year">Year</option>
            </select>
            <span id="connectedChartMeta">Loading...</span>
          </div>
        </div>
        <div id="connectedChart"></div>
      </aside>
    </section>
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
      <label>Rows
        <select name="limit">
          <option value="1000">1000</option>
          <option value="300">300</option>
          <option value="2500">2500</option>
          <option value="5000">5000</option>
          <option value="10000">10000</option>
        </select>
      </label>
      <div class="toolbar-actions" aria-label="Toolbar actions">
        <button type="button" class="secondary" id="clearFilters">Clear</button>
        <button type="button" class="secondary" id="reload">Reload</button>
      </div>
    </form>
    <div class="status" id="status"></div>
    <section class="layout">
      <div class="table-scroll">
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
      </div>
      <aside>
        <div class="detail-head">
          <h2>Event Detail</h2>
          <button type="button" class="icon-button" id="closeDetail" title="Close event detail" aria-label="Close event detail">&times;</button>
        </div>
        <section class="watch" id="churnWatch"></section>
        <div class="details" id="details">Select a log event.</div>
      </aside>
    </section>
  </main>
  <script>
    const filters = document.querySelector("#filters");
    const rows = document.querySelector("#rows");
    const statusEl = document.querySelector("#status");
    const details = document.querySelector("#details");
    const churnWatch = document.querySelector("#churnWatch");
    const statsEl = document.querySelector("#stats");
    const connectedChart = document.querySelector("#connectedChart");
    const connectedChartMeta = document.querySelector("#connectedChartMeta");
    const connectedRange = document.querySelector("#connectedRange");
    const sourceLine = document.querySelector("#sourceLine");
    const closeDetail = document.querySelector("#closeDetail");
    const IDLE_RELOAD_MS = 30 * 60 * 1000;
    let idleReloadTimer;
    let loadingPollTimer;

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
      return out;
    }

    async function loadFacets() {
      const data = await getJson("/api/facets");
      fill("category", data.categories);
      fill("eventName", data.eventNames);
      fill("os", data.operatingSystems);
      fill("gateway", data.gateways);
    }

    async function loadChurnWatch() {
      const data = await getJson("/api/churn?limit=8");
      churnWatch.innerHTML = '<div class="watch-title"><h3>Reconnect Watch</h3><span>last ' + esc(data.windowHours) + 'h</span></div>' +
        '<div class="watch-list">' + renderChurnUsers(data.users || [], data.excessiveCount) + '</div>';
    }

    function renderChurnUsers(users, excessiveCount) {
      if (!users.length) return '<div class="muted">Loading reconnect activity...</div>';
      const rows = excessiveCount ? users.filter(user => user.severity === "high" || user.severity === "elevated") : users.slice(0, 5);
      if (!rows.length) return '<div class="muted">No excessive reconnect pattern detected.</div>';
      return rows.map(user => '<div class="watch-user ' + esc(user.severity) + '">' +
        '<strong>' + esc(user.userName) + '</strong>' +
        '<span>' + esc(user.total) + ' events: ' + esc(user.connected) + ' connects, ' + esc(user.disconnected) + ' disconnects, ' + esc(user.shortSessions) + ' short sessions</span>' +
        '<span>Connected for ' + esc(formatDuration(user.connectedForSeconds)) + '</span>' +
      '</div>').join("");
    }

    async function loadConnectedChart() {
      const data = await getJson("/api/connected-users?range=" + encodeURIComponent(connectedRange.value));
      renderConnectedChart(data);
    }

    function renderConnectedChart(data) {
      const points = data.points || [];
      connectedChartMeta.textContent = points.length
        ? (data.source === "mysql" ? "MySQL, " : "live, ") + "excluding " + (data.excludedUsers ?? latestExcluded(points)) + " reconnect-heavy users"
        : "No connection data loaded";
      if (!points.length) {
        connectedChart.innerHTML = '<div class="muted">Loading connection trend...</div>';
        return;
      }

      const width = 340;
      const height = 82;
      const pad = { top: 8, right: 8, bottom: 18, left: 26 };
      const max = Math.max(1, ...points.map(point => point.connectedUsers));
      const plotW = width - pad.left - pad.right;
      const plotH = height - pad.top - pad.bottom;
      const x = index => pad.left + (points.length === 1 ? 0 : (index / (points.length - 1)) * plotW);
      const y = value => pad.top + plotH - (value / max) * plotH;
      const line = points.map((point, index) => x(index).toFixed(1) + "," + y(point.connectedUsers).toFixed(1)).join(" ");
      const area = pad.left + "," + (pad.top + plotH) + " " + line + " " + (pad.left + plotW) + "," + (pad.top + plotH);
      const last = points[points.length - 1];
      const grid = [0, .5, 1].map(part => {
        const gy = pad.top + plotH - part * plotH;
        const label = Math.round(max * part);
        return '<line class="chart-grid" x1="' + pad.left + '" y1="' + gy + '" x2="' + (pad.left + plotW) + '" y2="' + gy + '"></line>' +
          '<text class="chart-label" x="4" y="' + (gy + 4) + '">' + esc(label) + '</text>';
      }).join("");
      connectedChart.innerHTML = '<svg class="chart" viewBox="0 0 ' + width + ' ' + height + '" role="img" aria-label="Connected users over time">' +
        grid +
        '<polygon class="chart-area" points="' + area + '"></polygon>' +
        '<polyline class="chart-line" points="' + line + '"></polyline>' +
        '<circle class="chart-dot" cx="' + x(points.length - 1).toFixed(1) + '" cy="' + y(last.connectedUsers).toFixed(1) + '" r="3"></circle>' +
        '<text class="chart-label" x="' + pad.left + '" y="' + (height - 6) + '">' + esc(shortTime(points[0].timestamp)) + '</text>' +
        '<text class="chart-label" text-anchor="end" x="' + (pad.left + plotW) + '" y="' + (height - 6) + '">' + esc(shortTime(last.timestamp)) + '</text>' +
        '<text class="chart-label" text-anchor="end" x="' + (pad.left + plotW - 8) + '" y="' + Math.max(16, y(last.connectedUsers) - 8) + '">' + esc(last.connectedUsers) + ' users</text>' +
      '</svg>';
    }

    function latestExcluded(points) {
      const last = points[points.length - 1];
      return last && Number.isFinite(Number(last.excludedUsers)) ? Number(last.excludedUsers) : 0;
    }

    function shortTime(value) {
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return date.toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
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
      statusEl.textContent = data.loading ? "Loading logs..." : (data.error || "");
      statusEl.className = data.error ? "status error" : "status";
      const days = Object.entries(data.byDay || {});
      const max = Math.max(1, ...days.map(([, count]) => count));
      statsEl.innerHTML = [
        stat("Records", data.records),
        stat("Objects", data.objects),
        stat("Active users", data.activeUsers + " users / " + data.activeSessions + " sessions"),
        stat("Transfer", formatBytes((data.totalBytesIn || 0) + (data.totalBytesOut || 0))),
        '<div class="stat"><strong>' + days.length + '</strong><span>active days</span><div class="bars">' + days.map(([day, count]) => '<div class="bar" title="' + esc(day + ": " + count) + '" style="height:' + Math.max(5, Math.round((count / max) * 34)) + 'px"></div>').join("") + '</div></div>'
      ].join("");
      scheduleLoadingPoll(data.loading);
      return data;
    }

    function stat(label, value) {
      return '<div class="stat"><strong>' + esc(value) + '</strong><span>' + esc(label) + '</span></div>';
    }

    async function search() {
      const data = await getJson("/api/search?" + params());
      statusEl.textContent = (statusEl.className.includes("error") ? statusEl.textContent + " | " : "") + "searched " + data.searched + " loaded events; " + data.total + " matched; showing " + data.rows.length + " of " + data.limit;
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
      '</div>' + churnPanel(record.churn) + '<pre>' + esc(JSON.stringify(record.raw, null, 2)) + '</pre>';
    }

    function kv(key, value) {
      return '<div>' + esc(key) + '</div><div>' + esc(value || "-") + '</div>';
    }

    function churnPanel(churn) {
      if (!churn) return "";
      const recent = (churn.latest || []).map(item => '<div>' +
        esc(item.timestamp.replace("T", " ").replace("Z", "")) + " | " +
        esc(item.eventName) + " | " +
        esc(item.deviceName || "-") + " | " +
        esc(item.publicIp || "-") +
        (item.durationSeconds ? " | " + esc(formatDuration(item.durationSeconds)) : "") +
      '</div>').join("");
      return '<section class="churn ' + esc(churn.severity) + '">' +
        '<h3>Reconnect Activity</h3>' +
        '<div class="summary">' + esc(churn.message) + '</div>' +
        '<div class="mini-grid">' +
          miniStat(churn.connected, "connects") +
          miniStat(churn.disconnected, "disconnects") +
          miniStat(churn.shortSessions, "short sessions") +
          miniStat(formatDuration(churn.connectedForSeconds), "connected for") +
          miniStat(formatBytes(churn.totalTransfer), "transfer") +
        '</div>' +
        '<div class="mini-list">' + (recent || '<div>No recent connection events for this user.</div>') + '</div>' +
      '</section>';
    }

    function miniStat(value, label) {
      return '<div class="mini-stat"><strong>' + esc(value) + '</strong><span>' + esc(label) + '</span></div>';
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
    document.querySelector("#clearFilters").addEventListener("click", () => {
      filters.reset();
      search().catch(showError);
    });
    connectedRange.addEventListener("change", () => loadConnectedChart().catch(showError));

    function showError(error) {
      statusEl.textContent = error.message;
      statusEl.className = "status error";
    }

    async function boot() {
      await loadStats();
      await loadFacets();
      await loadChurnWatch();
      await loadConnectedChart();
      await search();
      resetIdleReloadTimer();
    }

    function scheduleLoadingPoll(isLoading) {
      clearTimeout(loadingPollTimer);
      if (!isLoading) return;
      loadingPollTimer = setTimeout(() => {
        boot().catch(showError);
      }, 5000);
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
  http.createServer(handler).listen(PORT, () => {
    console.log(`OpenVPN Log Search listening on http://localhost:${PORT}`);
    initMysql().catch((error) => {
      mysqlStatus = `unavailable: ${error.message}`;
      console.error(error);
    }).finally(() => refresh().catch((error) => {
      store = { ...store, error: error.message };
      console.error(error);
    }));
    if (AUTO_REFRESH_MINUTES > 0) {
      setInterval(() => {
        refresh().catch((error) => {
          store = { ...store, error: error.message };
          console.error(error);
        });
      }, AUTO_REFRESH_MINUTES * 60 * 1000);
    }
  });
}
