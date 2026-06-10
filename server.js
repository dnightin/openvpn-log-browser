const http = require("node:http");
const https = require("node:https");
const fs = require("node:fs/promises");
const path = require("node:path");
const zlib = require("node:zlib");
const crypto = require("node:crypto");
const querystring = require("node:querystring");
const { promisify } = require("node:util");

const gunzip = promisify(zlib.gunzip);

const PORT = Number(process.env.PORT || 3000);
const RAW_DIR = process.env.RAW_DIR || path.join(__dirname, "data", "raw");
const S3_CACHE_DIR = process.env.S3_CACHE_DIR || path.join(__dirname, "data", "s3-cache");
const S3_CACHE_OBJECT_DIR = path.join(S3_CACHE_DIR, "objects");
const S3_CACHE_MANIFEST_PATH = path.join(S3_CACHE_DIR, "manifest.json");
const SETTINGS_DIR = process.env.SETTINGS_DIR || path.join(__dirname, "data", "settings");
const SAML_SETTINGS_PATH = process.env.SAML_SETTINGS_PATH || path.join(SETTINGS_DIR, "saml.json");
const SOURCE_SETTINGS_PATH = process.env.SOURCE_SETTINGS_PATH || path.join(SETTINGS_DIR, "source.json");
const FETCH_CONCURRENCY = Math.max(1, Number(process.env.FETCH_CONCURRENCY || 32));
const LOAD_BATCH_DELAY_MS = Math.max(0, Number(process.env.LOAD_BATCH_DELAY_MS || 0));
const AUTO_REFRESH_MINUTES = Math.max(0, Number(process.env.AUTO_REFRESH_MINUTES || 30));
const ACTIVE_SESSION_MAX_AGE_HOURS = Math.max(1, Number(process.env.ACTIVE_SESSION_MAX_AGE_HOURS || 6));
const SESSION_COOKIE = "openvpn_log_browser_session";
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
let samlSettings = envSamlSettings();
let sourceSettings = null;
let objectRecordCache = new Map();
let objectRecordCacheSource = "";
const sessions = new Map();

function envSourceSettings() {
  const bucketUrl = ensureTrailingSlash(process.env.S3_BUCKET_URL || "https://wc-openvpnlogs.s3.us-east-1.amazonaws.com/");
  return cleanSourceSettings({
    mode: process.env.S3_FETCH_MODE || process.env.LOG_SOURCE_MODE || "http",
    bucketUrl,
    bucketName: process.env.S3_BUCKET_NAME || bucketNameFromUrl(bucketUrl),
    region: process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || "us-east-1",
    logPrefix: process.env.LOG_PREFIX || "CloudConnexa/wellesley/"
  });
}

async function loadSourceSettings() {
  try {
    const saved = JSON.parse(await fs.readFile(SOURCE_SETTINGS_PATH, "utf8"));
    sourceSettings = { ...envSourceSettings(), ...cleanSourceSettings(saved) };
  } catch (error) {
    if (error.code !== "ENOENT") console.error(error);
    sourceSettings = envSourceSettings();
  }
}

async function saveSourceSettings(settings) {
  const cleaned = cleanSourceSettings(settings);
  await fs.mkdir(path.dirname(SOURCE_SETTINGS_PATH), { recursive: true });
  await fs.writeFile(SOURCE_SETTINGS_PATH, JSON.stringify(cleaned, null, 2));
  sourceSettings = { ...envSourceSettings(), ...cleaned };
}

function cleanSourceSettings(settings = {}) {
  const bucketUrl = ensureTrailingSlash(String(settings.bucketUrl || "").trim());
  const bucketName = String(settings.bucketName || bucketNameFromUrl(bucketUrl) || "").trim();
  return {
    mode: settings.mode === "s3-api" ? "s3-api" : "http",
    bucketUrl,
    bucketName,
    region: String(settings.region || "us-east-1").trim() || "us-east-1",
    logPrefix: String(settings.logPrefix || "").trim().replace(/^\/+/, "")
  };
}

function publicSourceSettings() {
  const settings = sourceConfig();
  return {
    ...settings,
    hasIamCredentialEnv: Boolean(process.env.AWS_ACCESS_KEY_ID || process.env.AWS_PROFILE || process.env.AWS_WEB_IDENTITY_TOKEN_FILE || process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)
  };
}

function sourceConfig() {
  return sourceSettings || envSourceSettings();
}

function envSamlSettings() {
  return {
    enabled: toBool(process.env.SAML_ENABLED),
    requireAuth: toBool(process.env.SAML_REQUIRE_AUTH),
    issuer: process.env.SAML_SP_ENTITY_ID || process.env.SAML_ISSUER || "openvpn-log-browser",
    callbackUrl: process.env.SAML_CALLBACK_URL || "",
    entryPoint: process.env.SAML_ENTRY_POINT || "",
    logoutUrl: process.env.SAML_LOGOUT_URL || "",
    idpCert: process.env.SAML_IDP_CERT || "",
    audience: process.env.SAML_AUDIENCE || "",
    wantAssertionsSigned: process.env.SAML_WANT_ASSERTIONS_SIGNED !== "false",
    wantAuthnResponseSigned: toBool(process.env.SAML_WANT_RESPONSE_SIGNED),
    disableRequestedAuthnContext: process.env.SAML_DISABLE_REQUESTED_AUTHN_CONTEXT !== "false"
  };
}

function toBool(value) {
  return value === true || value === "true" || value === "1" || value === "yes";
}

function ensureTrailingSlash(value) {
  if (!value) return "";
  return value.endsWith("/") ? value : `${value}/`;
}

function bucketNameFromUrl(value) {
  try {
    const host = new URL(value).hostname;
    const match = host.match(/^([^.]+)\.s3[.-]/);
    return match ? match[1] : "";
  } catch {
    return "";
  }
}

async function loadSamlSettings() {
  try {
    const saved = JSON.parse(await fs.readFile(SAML_SETTINGS_PATH, "utf8"));
    samlSettings = { ...envSamlSettings(), ...cleanSamlSettings(saved) };
  } catch (error) {
    if (error.code !== "ENOENT") console.error(error);
    samlSettings = envSamlSettings();
  }
}

async function saveSamlSettings(settings) {
  const cleaned = cleanSamlSettings(settings);
  await fs.mkdir(path.dirname(SAML_SETTINGS_PATH), { recursive: true });
  await fs.writeFile(SAML_SETTINGS_PATH, JSON.stringify(cleaned, null, 2));
  samlSettings = { ...envSamlSettings(), ...cleaned };
}

function cleanSamlSettings(settings = {}) {
  return {
    enabled: Boolean(settings.enabled),
    requireAuth: Boolean(settings.requireAuth),
    issuer: String(settings.issuer || "openvpn-log-browser").trim(),
    callbackUrl: String(settings.callbackUrl || "").trim(),
    entryPoint: String(settings.entryPoint || "").trim(),
    logoutUrl: String(settings.logoutUrl || "").trim(),
    idpCert: String(settings.idpCert || "").trim(),
    audience: String(settings.audience || "").trim(),
    wantAssertionsSigned: settings.wantAssertionsSigned !== false,
    wantAuthnResponseSigned: Boolean(settings.wantAuthnResponseSigned),
    disableRequestedAuthnContext: settings.disableRequestedAuthnContext !== false
  };
}

function publicSamlSettings(req) {
  const settings = samlConfig(req);
  return {
    enabled: settings.enabled,
    requireAuth: settings.requireAuth,
    issuer: settings.issuer,
    callbackUrl: settings.callbackUrl,
    entryPoint: settings.entryPoint,
    logoutUrl: settings.logoutUrl,
    audience: settings.audience,
    wantAssertionsSigned: settings.wantAssertionsSigned,
    wantAuthnResponseSigned: settings.wantAuthnResponseSigned,
    disableRequestedAuthnContext: settings.disableRequestedAuthnContext,
    hasIdpCert: Boolean(settings.idpCert),
    idpCert: settings.idpCert,
    metadataUrl: `${requestOrigin(req)}/auth/saml/metadata`
  };
}

function samlConfig(req) {
  const origin = requestOrigin(req);
  return {
    ...samlSettings,
    callbackUrl: samlSettings.callbackUrl || `${origin}/auth/saml/callback`
  };
}

function requestOrigin(req) {
  const proto = req.headers["x-forwarded-proto"] || "http";
  return `${proto}://${req.headers.host || `localhost:${PORT}`}`;
}

function samlReady(req) {
  const settings = samlConfig(req);
  return Boolean(settings.enabled && settings.entryPoint && settings.idpCert && settings.issuer);
}

function getSaml(req) {
  const settings = samlConfig(req);
  const { SAML } = require("@node-saml/node-saml");
  return new SAML({
    entryPoint: settings.entryPoint,
    issuer: settings.issuer,
    callbackUrl: settings.callbackUrl,
    idpCert: settings.idpCert,
    audience: settings.audience || settings.issuer,
    wantAssertionsSigned: settings.wantAssertionsSigned,
    wantAuthnResponseSigned: settings.wantAuthnResponseSigned,
    disableRequestedAuthnContext: settings.disableRequestedAuthnContext
  });
}

function currentUser(req) {
  const cookies = parseCookies(req.headers.cookie || "");
  const sessionId = cookies[SESSION_COOKIE];
  const session = sessionId ? sessions.get(sessionId) : null;
  if (!session) return { authenticated: false, name: "", email: "", source: "none" };
  session.lastSeen = Date.now();
  return { authenticated: true, ...session.user };
}

function createSession(res, profile = {}) {
  const sessionId = crypto.randomBytes(32).toString("base64url");
  const user = {
    name: profile.displayName || profile.name || profile.cn || profile.email || profile.nameID || "SAML user",
    email: profile.email || profile.mail || profile.nameID || "",
    source: "saml"
  };
  sessions.set(sessionId, { user, createdAt: Date.now(), lastSeen: Date.now() });
  setCookie(res, SESSION_COOKIE, sessionId, { httpOnly: true, sameSite: "Lax", path: "/" });
  return user;
}

function clearSession(req, res) {
  const cookies = parseCookies(req.headers.cookie || "");
  if (cookies[SESSION_COOKIE]) sessions.delete(cookies[SESSION_COOKIE]);
  setCookie(res, SESSION_COOKIE, "", { maxAge: 0, httpOnly: true, sameSite: "Lax", path: "/" });
}

function parseCookies(header) {
  return Object.fromEntries(header.split(";").map((part) => {
    const [key, ...rest] = part.trim().split("=");
    return [key, decodeURIComponent(rest.join("=") || "")];
  }).filter(([key]) => key));
}

function setCookie(res, name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  if (options.path) parts.push(`Path=${options.path}`);
  res.setHeader("Set-Cookie", parts.join("; "));
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

async function readRequestBody(req, limit = 2 * 1024 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new Error("Request body too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function readJsonBody(req) {
  const body = await readRequestBody(req);
  return body ? JSON.parse(body) : {};
}

async function samlLogin(req, res) {
  if (!samlReady(req)) return json(res, { error: "SAML is not configured." }, 400);
  const redirectTo = new URL(req.url, requestOrigin(req)).searchParams.get("returnTo") || "/";
  const saml = getSaml(req);
  const url = await saml.getAuthorizeUrlAsync(redirectTo, undefined, {});
  redirect(res, url);
}

async function samlCallback(req, res) {
  if (!samlReady(req)) return json(res, { error: "SAML is not configured." }, 400);
  const body = querystring.parse(await readRequestBody(req));
  const result = await getSaml(req).validatePostResponseAsync(body);
  createSession(res, result.profile || result);
  redirect(res, String(body.RelayState || "/"));
}

async function samlMetadata(req, res) {
  if (!samlReady(req)) return json(res, { error: "SAML is not configured." }, 400);
  const metadata = getSaml(req).generateServiceProviderMetadata(null, null);
  res.writeHead(200, { "Content-Type": "application/xml; charset=utf-8" });
  res.end(metadata);
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

function parseS3List(xml, logPrefix) {
  const objects = [];
  const contentRe = /<Contents>([\s\S]*?)<\/Contents>/g;
  let match;
  while ((match = contentRe.exec(xml))) {
    const block = match[1];
    const key = xmlText(block, "Key");
    if (!key || !key.startsWith(logPrefix) || !key.endsWith(".jsonl.gz")) continue;
    objects.push({
      key,
      lastModified: xmlText(block, "LastModified"),
      size: Number(xmlText(block, "Size") || 0),
      etag: xmlText(block, "ETag").replaceAll("&quot;", "\"")
    });
  }
  return objects.sort((a, b) => a.key.localeCompare(b.key));
}

function sortS3Objects(objects) {
  return objects.sort((a, b) => {
    const aTime = Date.parse(a.lastModified);
    const bTime = Date.parse(b.lastModified);
    if (Number.isFinite(aTime) && Number.isFinite(bTime) && aTime !== bTime) return bTime - aTime;
    if (Number.isFinite(aTime) !== Number.isFinite(bTime)) return Number.isFinite(bTime) ? 1 : -1;
    return b.key.localeCompare(a.key);
  });
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

async function listBucketObjectsHttp(config) {
  const objects = [];
  let marker = "";
  for (;;) {
    const pageUrl = marker ? `${config.bucketUrl}?marker=${encodeURIComponent(marker)}` : config.bucketUrl;
    const xml = (await httpGetBuffer(pageUrl)).toString("utf8");
    const pageObjects = parseS3List(xml, config.logPrefix);
    objects.push(...pageObjects);
    const isTruncated = xmlText(xml, "IsTruncated").toLowerCase() === "true";
    if (!isTruncated || pageObjects.length === 0) break;
    marker = pageObjects[pageObjects.length - 1].key;
  }
  return sortS3Objects(objects);
}

async function s3Api() {
  const sdk = require("@aws-sdk/client-s3");
  return sdk;
}

async function s3Client(config) {
  const { S3Client } = await s3Api();
  return new S3Client({ region: config.region });
}

async function listBucketObjectsApi(config) {
  if (!config.bucketName) throw new Error("S3 bucket name is required for S3 API mode.");
  const { ListObjectsV2Command } = await s3Api();
  const client = await s3Client(config);
  const objects = [];
  let ContinuationToken;
  do {
    const page = await client.send(new ListObjectsV2Command({
      Bucket: config.bucketName,
      Prefix: config.logPrefix,
      ContinuationToken
    }));
    for (const object of page.Contents || []) {
      if (!object.Key || !object.Key.endsWith(".jsonl.gz")) continue;
      objects.push({
        key: object.Key,
        lastModified: object.LastModified ? object.LastModified.toISOString() : "",
        size: Number(object.Size || 0),
        etag: object.ETag || ""
      });
    }
    ContinuationToken = page.IsTruncated ? page.NextContinuationToken : undefined;
  } while (ContinuationToken);
  return sortS3Objects(objects);
}

async function getObjectBufferApi(config, key, client) {
  const { GetObjectCommand } = await s3Api();
  const object = await client.send(new GetObjectCommand({ Bucket: config.bucketName, Key: key }));
  return streamToBuffer(object.Body);
}

async function streamToBuffer(stream) {
  if (!stream) return Buffer.alloc(0);
  if (Buffer.isBuffer(stream)) return stream;
  if (typeof stream.transformToByteArray === "function") {
    return Buffer.from(await stream.transformToByteArray());
  }
  const chunks = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
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
  const config = sourceConfig();
  const apiMode = config.mode === "s3-api";
  const sourceId = sourceCacheId(config);
  if (objectRecordCacheSource !== sourceId) {
    objectRecordCache = new Map();
    objectRecordCacheSource = sourceId;
  }
  const objects = apiMode ? await listBucketObjectsApi(config) : await listBucketObjectsHttp(config);
  const client = apiMode ? await s3Client(config) : null;
  const manifest = await loadS3CacheManifest(sourceId);
  const records = [];
  const failed = [];
  const pending = [];
  const seenKeys = new Set();
  let reusedMemory = 0;
  let reusedDisk = 0;
  let downloaded = 0;
  let batchesSinceManifestSave = 0;

  for (const object of objects) {
    seenKeys.add(object.key);
    const fingerprint = objectFingerprint(object);
    const cached = objectRecordCache.get(object.key);
    if (cached && cached.fingerprint === fingerprint) {
      records.push(...cached.records);
      reusedMemory += 1;
    } else {
      pending.push({ ...object, fingerprint });
    }
  }

  for (const key of objectRecordCache.keys()) {
    if (!seenKeys.has(key)) objectRecordCache.delete(key);
  }
  for (const key of Object.keys(manifest.objects)) {
    if (!seenKeys.has(key)) delete manifest.objects[key];
  }

  for (let index = 0; index < pending.length; index += FETCH_CONCURRENCY) {
    const batch = pending.slice(index, index + FETCH_CONCURRENCY);
    const batchRecords = await Promise.all(batch.map(async (object) => {
      const cached = objectRecordCache.get(object.key);
      try {
        let compressed = await readCachedS3Object(manifest, object);
        if (compressed) {
          reusedDisk += 1;
        } else {
          compressed = apiMode
            ? await getObjectBufferApi(config, object.key, client)
            : await httpGetBuffer(config.bucketUrl + object.key.split("/").map(encodeURIComponent).join("/"));
          await writeCachedS3Object(manifest, object, compressed);
          downloaded += 1;
        }
        const parsed = await parseObject(compressed, object.key);
        objectRecordCache.set(object.key, { fingerprint: object.fingerprint, records: parsed });
        return parsed;
      } catch (error) {
        if (cached) {
          failed.push(`${object.key}: ${error.message}; used cached records`);
          return cached.records;
        }
        failed.push(`${object.key}: ${error.message}`);
        return [];
      }
    }));
    for (const objectRecords of batchRecords) records.push(...objectRecords);
    store = {
      ...store,
      records,
      source: apiMode ? `s3://${config.bucketName}/${config.logPrefix}` : config.bucketUrl,
      objects,
      error: `Loading S3 objects ${Math.min(index + batch.length, pending.length)} of ${pending.length} not in memory; memory ${reusedMemory}, disk ${reusedDisk}, downloaded ${downloaded}.`
    };
    batchesSinceManifestSave += 1;
    if (batchesSinceManifestSave >= 25) {
      await saveS3CacheManifest(manifest, seenKeys);
      batchesSinceManifestSave = 0;
    }
    await yieldToEventLoop(LOAD_BATCH_DELAY_MS);
  }
  await saveS3CacheManifest(manifest, seenKeys);
  return {
    records,
    objects,
    source: apiMode ? `s3://${config.bucketName}/${config.logPrefix}` : config.bucketUrl,
    error: failed.length ? `Skipped ${failed.length} S3 object(s) after retries. First error: ${failed[0]}` : null
  };
}

function sourceCacheId(config) {
  return [config.mode, config.bucketUrl, config.bucketName, config.region, config.logPrefix].join("|");
}

function objectFingerprint(object) {
  return [object.etag || "", object.size || 0, object.lastModified || ""].join("|");
}

async function loadS3CacheManifest(sourceId) {
  try {
    const manifest = JSON.parse(await fs.readFile(S3_CACHE_MANIFEST_PATH, "utf8"));
    if (manifest.sourceId !== sourceId || !manifest.objects || typeof manifest.objects !== "object") {
      return { version: 1, sourceId, objects: {} };
    }
    return manifest;
  } catch (error) {
    if (error.code !== "ENOENT") console.error(error);
    return { version: 1, sourceId, objects: {} };
  }
}

async function saveS3CacheManifest(manifest, seenKeys) {
  for (const key of Object.keys(manifest.objects)) {
    if (!seenKeys.has(key)) delete manifest.objects[key];
  }
  await fs.mkdir(S3_CACHE_DIR, { recursive: true });
  await fs.writeFile(S3_CACHE_MANIFEST_PATH, JSON.stringify({
    version: 1,
    sourceId: manifest.sourceId,
    updatedAt: new Date().toISOString(),
    objects: manifest.objects
  }, null, 2));
}

async function readCachedS3Object(manifest, object) {
  const entry = manifest.objects[object.key];
  const filePath = cachePathForS3Key(object.key);
  if (!entry || entry.fingerprint !== object.fingerprint) {
    try {
      const stat = await fs.stat(filePath);
      if (Number(object.size || 0) && stat.size !== Number(object.size || 0)) return null;
      const compressed = await fs.readFile(filePath);
      manifest.objects[object.key] = cacheManifestEntry(object, filePath);
      return compressed;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      return null;
    }
  }
  try {
    return await fs.readFile(filePath);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    delete manifest.objects[object.key];
    return null;
  }
}

async function writeCachedS3Object(manifest, object, compressed) {
  const filePath = cachePathForS3Key(object.key);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.${process.pid}.tmp`;
  await fs.writeFile(tempPath, compressed);
  await fs.rename(tempPath, filePath);
  manifest.objects[object.key] = cacheManifestEntry(object, filePath);
}

function cacheManifestEntry(object, filePath) {
  return {
    fingerprint: object.fingerprint,
    size: object.size,
    etag: object.etag,
    lastModified: object.lastModified,
    path: path.relative(S3_CACHE_DIR, filePath).replaceAll(path.sep, "/"),
    cachedAt: new Date().toISOString()
  };
}

function cachePathForS3Key(key) {
  const parts = key.split("/").filter(Boolean).map((part) => encodeURIComponent(part));
  return path.join(S3_CACHE_OBJECT_DIR, ...parts);
}

function yieldToEventLoop(delayMs = 0) {
  if (delayMs > 0) return new Promise((resolve) => setTimeout(resolve, delayMs));
  return new Promise((resolve) => setImmediate(resolve));
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
  const newest = newestRecordTimestamp();
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
  const newest = newestRecordTimestamp();
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

function newestRecordTimestamp() {
  let newest = 0;
  for (const record of store.records) {
    const ts = Date.parse(record.timestamp);
    if (Number.isFinite(ts) && ts > newest) newest = ts;
  }
  return newest || Date.now();
}

function connectedUsersSnapshot() {
  const newest = newestRecordTimestamp();
  const cutoff = newest - (24 * 60 * 60 * 1000);
  const excludedUsers = excessiveReconnectUsers(newest, cutoff);
  const activeRows = latestActiveConnections(newest).filter((session) => !excludedUsers.has(session.userName));
  const activeUsers = new Set(activeRows.map((session) => session.userName));
  return {
    connectedUsers: activeUsers.size,
    excludedUsers: excludedUsers.size,
    generatedAt: new Date(newest).toISOString()
  };
}

function latestActiveConnections(atTime = newestRecordTimestamp()) {
  const staleCutoff = atTime - (ACTIVE_SESSION_MAX_AGE_HOURS * 60 * 60 * 1000);
  const latestByUser = new Map();
  for (const record of store.records) {
    if (record.eventName !== "client-connected" && record.eventName !== "client-disconnected") continue;
    const userName = record.userName || record.parentEntityName || record.initiatorName;
    if (!userName) continue;
    const timestamp = Date.parse(record.timestamp);
    if (!Number.isFinite(timestamp) || timestamp > atTime) continue;
    const previous = latestByUser.get(userName);
    const disconnectedWinsTie = previous && timestamp === previous.timestamp && record.eventName === "client-disconnected";
    if (!previous || timestamp > previous.timestamp || disconnectedWinsTie) {
      latestByUser.set(userName, {
        sessionId: record.sessionId || "",
        userName,
        eventName: record.eventName,
        timestamp
      });
    }
  }
  return [...latestByUser.values()].filter((session) =>
    session.eventName === "client-connected" && session.timestamp >= staleCutoff
  );
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
  const newest = newestRecordTimestamp();
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

function stats(timeZone = "UTC") {
  const displayTimeZone = normalizeTimeZone(timeZone);
  const timestamps = store.records.map((record) => record.timestamp).filter(Boolean).sort();
  const byDay = {};
  const byEvent = {};
  let totalBytesIn = 0;
  let totalBytesOut = 0;
  for (const record of store.records) {
    const day = dayInTimeZone(record.timestamp, displayTimeZone);
    if (!day) continue;
    byDay[day] = (byDay[day] || 0) + 1;
    if (record.eventName) byEvent[record.eventName] = (byEvent[record.eventName] || 0) + 1;
    totalBytesIn += record.bytesIn || 0;
    totalBytesOut += record.bytesOut || 0;
  }
  const newest = timestamps.length ? Date.parse(timestamps[timestamps.length - 1]) : Date.now();
  const activeSessionRows = latestActiveConnections(newest);
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
    timeZone: displayTimeZone,
    byDay
  };
}

function normalizeTimeZone(timeZone) {
  try {
    Intl.DateTimeFormat("en-US", { timeZone }).format(new Date());
    return timeZone;
  } catch {
    return "UTC";
  }
}

function dayInTimeZone(value, timeZone) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).formatToParts(date);
  const byType = Object.fromEntries(parts.map((part) => [part.type, part.value]));
  return `${byType.year}-${byType.month}-${byType.day}`;
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
    if (url.pathname === "/auth/saml/login") return samlLogin(req, res);
    if (url.pathname === "/auth/saml/callback" && req.method === "POST") return samlCallback(req, res);
    if (url.pathname === "/auth/saml/metadata") return samlMetadata(req, res);
    if (url.pathname === "/auth/logout") {
      clearSession(req, res);
      return redirect(res, "/");
    }
    if (samlSettings.requireAuth && !currentUser(req).authenticated && url.pathname !== "/" && url.pathname !== "/api/auth") return json(res, { error: "Authentication required" }, 401);
    if (url.pathname === "/") return html(res);
    if (url.pathname === "/api/auth") return json(res, { user: currentUser(req), saml: { enabled: samlConfig(req).enabled, ready: samlReady(req), requireAuth: samlConfig(req).requireAuth } });
    if (url.pathname === "/api/settings/saml" && req.method === "GET") return json(res, publicSamlSettings(req));
    if (url.pathname === "/api/settings/saml" && req.method === "POST") {
      const nextSettings = cleanSamlSettings(await readJsonBody(req));
      if (nextSettings.requireAuth && (!nextSettings.enabled || !nextSettings.entryPoint || !nextSettings.idpCert || !nextSettings.issuer)) {
        return json(res, { error: "Require SSO can only be enabled after SAML login URL, entity ID, and IdP certificate are configured." }, 400);
      }
      await saveSamlSettings(nextSettings);
      return json(res, publicSamlSettings(req));
    }
    if (url.pathname === "/api/settings/source" && req.method === "GET") return json(res, publicSourceSettings());
    if (url.pathname === "/api/settings/source" && req.method === "POST") {
      const nextSettings = cleanSourceSettings(await readJsonBody(req));
      if (nextSettings.mode === "http" && !nextSettings.bucketUrl) return json(res, { error: "S3 bucket URL is required for HTTP mode." }, 400);
      if (nextSettings.mode === "s3-api" && !nextSettings.bucketName) return json(res, { error: "S3 bucket name is required for S3 API mode." }, 400);
      await saveSourceSettings(nextSettings);
      return json(res, publicSourceSettings());
    }
    if (url.pathname === "/api/stats") return json(res, stats(url.searchParams.get("timeZone") || "UTC"));
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
    body { margin: 0; background: var(--bg); color: var(--text); height: 100vh; height: 100dvh; overflow: hidden; }
    header { background: #111827; color: white; padding: 10px 24px; display: flex; align-items: center; justify-content: space-between; gap: 18px; }
    .brand { min-width: 0; }
    header h1 { margin: 0; font-size: 20px; font-weight: 720; letter-spacing: 0; }
    header .sub { margin-top: 3px; color: #cbd5e1; font-size: 12px; }
    .account { position: relative; flex: 0 0 auto; }
    .menu-button { background: transparent; border-color: #374151; color: white; display: inline-flex; align-items: center; gap: 8px; }
    .menu-button:hover { background: #1f2937; }
    .account-menu { position: absolute; right: 0; top: calc(100% + 8px); width: 220px; background: white; border: 1px solid var(--line); border-radius: 8px; box-shadow: 0 14px 28px rgba(15, 23, 42, .18); padding: 6px; display: none; z-index: 5; }
    .account.open .account-menu { display: grid; gap: 4px; }
    .account-menu button, .account-menu a { height: 34px; border: 0; background: white; color: var(--text); border-radius: 6px; padding: 0 9px; text-align: left; text-decoration: none; display: flex; align-items: center; font-weight: 650; }
    .account-menu button:hover, .account-menu a:hover { background: #f1f5f9; }
    .account-name { padding: 7px 9px; color: var(--muted); font-size: 12px; border-bottom: 1px solid var(--line); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    main { padding: 12px 24px 22px; max-width: 1500px; margin: 0 auto; height: calc(100vh - 57px); height: calc(100dvh - 57px); display: flex; flex-direction: column; min-height: 0; width: 100%; }
    .dashboard-top { display: grid; grid-template-columns: minmax(160px, 210px) minmax(340px, 1fr) minmax(260px, 320px); gap: 10px; margin-bottom: 10px; align-items: stretch; flex: 0 0 auto; }
    .stats { display: grid; grid-template-columns: 1fr; gap: 10px; min-width: 0; }
    .stat { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; min-width: 0; min-height: 104px; }
    .stat strong { display: block; font-size: 19px; line-height: 1.25; }
    .stat span { color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
    .chart-panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 9px 10px; min-height: 104px; min-width: 0; overflow: hidden; }
    .chart-head { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; align-items: start; margin-bottom: 5px; }
    .chart-head h2 { margin: 0; font-size: 13px; line-height: 1.25; }
    .chart-head span { color: var(--muted); font-size: 11px; display: block; margin-top: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .chart-controls { display: grid; justify-items: end; gap: 3px; min-width: 0; }
    .chart-controls select { height: 28px; padding: 0 7px; font-size: 12px; }
    .chart { width: 100%; height: 76px; display: block; }
    .chart-grid { stroke: #e5e9f0; stroke-width: 1; }
    .chart-line { fill: none; stroke: var(--accent); stroke-width: 3; stroke-linecap: round; stroke-linejoin: round; }
    .chart-area { fill: rgba(22, 108, 125, .12); }
    .chart-dot { fill: var(--accent); }
    .chart-label { fill: var(--muted); font-size: 11px; }
    .toolbar { display: grid; grid-template-columns: minmax(220px, 1fr) minmax(120px, 150px) minmax(130px, 160px) minmax(110px, 130px) minmax(140px, 170px) minmax(110px, 140px) minmax(110px, 140px) 90px 140px; gap: 8px; align-items: end; margin-bottom: 8px; flex: 0 0 auto; }
    label { display: grid; gap: 4px; color: var(--muted); font-size: 12px; font-weight: 650; }
    input, select, button { height: 34px; border-radius: 7px; border: 1px solid var(--line); background: white; color: var(--text); padding: 0 10px; font: inherit; min-width: 0; }
    button { background: var(--accent); color: white; border-color: var(--accent); cursor: pointer; font-weight: 700; }
    button.secondary { background: white; color: var(--accent); }
    .toolbar-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; align-self: end; }
    .toolbar-actions button { width: 100%; }
    .status { margin: 4px 0 8px; color: var(--muted); font-size: 12px; min-height: 16px; flex: 0 0 auto; }
    .status.error { color: var(--danger); }
    .muted { color: var(--muted); font-size: 12px; }
    dialog { border: 1px solid var(--line); border-radius: 8px; padding: 0; width: min(760px, calc(100vw - 24px)); max-height: calc(100vh - 40px); box-shadow: 0 24px 80px rgba(15, 23, 42, .24); }
    dialog::backdrop { background: rgba(15, 23, 42, .4); }
    .settings { padding: 16px; display: grid; gap: 14px; }
    .settings header { background: transparent; color: var(--text); padding: 0 0 10px; border-bottom: 1px solid var(--line); }
    .settings h2, .settings h3 { margin: 0; }
    .settings-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .settings textarea { min-height: 130px; resize: vertical; border-radius: 7px; border: 1px solid var(--line); padding: 9px 10px; font: inherit; }
    .settings .wide { grid-column: 1 / -1; }
    .check-row { display: flex; align-items: center; gap: 8px; min-height: 38px; color: var(--text); }
    .check-row input { height: auto; }
    .settings-actions { display: flex; justify-content: flex-end; gap: 8px; border-top: 1px solid var(--line); padding-top: 12px; }
    .layout { display: grid; grid-template-columns: minmax(0, 1fr); gap: 12px; align-items: stretch; min-height: 0; flex: 1 1 auto; }
    .layout.detail-open { grid-template-columns: minmax(0, 1fr) minmax(320px, 380px); }
    .table-scroll { min-height: 0; overflow: auto; border: 1px solid var(--line); border-radius: 8px; background: var(--panel); contain: size layout paint; }
    table { width: max-content; min-width: 100%; table-layout: fixed; border-collapse: collapse; background: var(--panel); }
    th, td { padding: 7px 9px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 13px; overflow: hidden; text-overflow: ellipsis; }
    th { color: var(--muted); background: #f1f5f9; font-size: 12px; position: sticky; top: 0; z-index: 1; user-select: none; }
    th .th-label { display: block; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; padding-right: 9px; }
    .col-resizer { position: absolute; top: 0; right: -3px; width: 7px; height: 100%; cursor: col-resize; touch-action: none; z-index: 2; }
    .col-resizer::after { content: ""; position: absolute; top: 8px; bottom: 8px; left: 3px; width: 1px; background: transparent; }
    th:hover .col-resizer::after, body.resizing-columns .col-resizer::after { background: #aab4c3; }
    body.resizing-columns { cursor: col-resize; user-select: none; }
    tr { cursor: pointer; }
    tr:hover td { background: #f8fbfc; }
    tr.selected td { background: #eef8fb; }
    td.time { white-space: nowrap; font-variant-numeric: tabular-nums; }
    td.ip, td.user, td.op { overflow-wrap: anywhere; }
    td.wrap { white-space: normal; overflow-wrap: anywhere; }
    .chip { display: inline-flex; align-items: center; min-height: 23px; padding: 2px 8px; border-radius: 999px; background: var(--chip); color: #28505a; font-size: 12px; font-weight: 650; }
    aside { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; min-height: 0; overflow: auto; }
    .detail-panel[hidden] { display: none; }
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
    .watch { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 9px 10px; min-height: 104px; min-width: 0; overflow: hidden; }
    .watch-title { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; margin-bottom: 6px; }
    .watch-title h3 { margin: 0; font-size: 13px; }
    .watch-title span { color: var(--muted); font-size: 11px; }
    .watch-list { display: grid; gap: 4px; }
    .watch-user { border: 1px solid #dce7df; border-left: 5px solid #2f8f46; border-radius: 7px; padding: 4px 7px; background: white; display: flex; justify-content: space-between; align-items: center; gap: 10px; min-height: 24px; }
    .watch-user.elevated { border-color: #ead3a8; background: white; }
    .watch-user.high { border-color: #efc7cc; background: white; }
    .watch-user.elevated { border-left-color: #d99a2b; }
    .watch-user.high { border-left-color: var(--danger); }
    .watch-user-link { display: block; height: auto; min-width: 0; padding: 0; border: 0; border-radius: 0; background: transparent; color: var(--text); font-size: 12px; font-weight: 700; line-height: 1.25; text-align: left; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: pointer; }
    .watch-user-link:hover { color: var(--accent); text-decoration: underline; }
    .watch-user-link:focus-visible { outline: 2px solid rgba(22, 108, 125, .35); outline-offset: 2px; }
    .watch-user span { color: var(--muted); display: block; font-size: 11px; white-space: nowrap; }
    .watch-more { color: var(--muted); font-size: 11px; padding: 1px 2px 0 7px; }
    pre { margin: 0; padding: 12px; background: #0f172a; color: #dbeafe; border-radius: 8px; overflow: auto; max-height: 520px; font-size: 12px; line-height: 1.45; }
    @media (max-width: 1100px) {
      .toolbar { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 820px) {
      .dashboard-top { grid-template-columns: 1fr; }
      .stats { grid-template-columns: 1fr; }
      .layout { grid-template-columns: 1fr; }
      aside { min-height: 420px; }
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
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <h1>OpenVPN Log Search</h1>
      <div class="sub" id="sourceLine">Loading authorized CloudConnexa audit logs...</div>
    </div>
    <div class="account" id="accountMenu">
      <button type="button" class="menu-button" id="accountMenuButton" aria-haspopup="true" aria-expanded="false">Account</button>
      <div class="account-menu" role="menu">
        <div class="account-name" id="accountName">Not signed in</div>
        <a href="/auth/saml/login" id="loginLink" role="menuitem">Login</a>
        <a href="/auth/logout" id="logoutLink" role="menuitem">Logout</a>
        <button type="button" id="settingsButton" role="menuitem">Settings</button>
      </div>
    </div>
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
      <section class="watch" id="churnWatch">
        <div class="watch-title"><h3>Reconnect Watch</h3><span>last 24h</span></div>
        <div class="watch-list"><div class="muted">Loading reconnect activity...</div></div>
      </section>
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
    <section class="layout" id="layout">
      <div class="table-scroll">
        <table id="eventsTable">
          <colgroup>
            <col data-col="time">
            <col data-col="user">
            <col data-col="event">
            <col data-col="device">
            <col data-col="ip">
            <col data-col="gateway">
            <col data-col="duration">
            <col data-col="transfer">
          </colgroup>
          <thead>
            <tr>
              <th data-col="time"><span class="th-label">Time</span><span class="col-resizer" role="separator" aria-label="Resize Time column"></span></th>
              <th data-col="user"><span class="th-label">User</span><span class="col-resizer" role="separator" aria-label="Resize User column"></span></th>
              <th data-col="event"><span class="th-label">Event</span><span class="col-resizer" role="separator" aria-label="Resize Event column"></span></th>
              <th data-col="device"><span class="th-label">Device</span><span class="col-resizer" role="separator" aria-label="Resize Device column"></span></th>
              <th data-col="ip"><span class="th-label">IP / Tunnel</span><span class="col-resizer" role="separator" aria-label="Resize IP / Tunnel column"></span></th>
              <th data-col="gateway"><span class="th-label">Gateway</span><span class="col-resizer" role="separator" aria-label="Resize Gateway column"></span></th>
              <th data-col="duration"><span class="th-label">Duration</span><span class="col-resizer" role="separator" aria-label="Resize Duration column"></span></th>
              <th data-col="transfer"><span class="th-label">Transfer</span><span class="col-resizer" role="separator" aria-label="Resize Transfer column"></span></th>
            </tr>
          </thead>
          <tbody id="rows"></tbody>
        </table>
      </div>
      <aside class="detail-panel" id="detailPanel" hidden>
        <div class="detail-head">
          <h2>Event Detail</h2>
          <button type="button" class="icon-button" id="closeDetail" title="Close event detail" aria-label="Close event detail">&times;</button>
        </div>
        <div class="details" id="details">Select a log event.</div>
      </aside>
    </section>
  </main>
  <dialog id="settingsDialog">
    <form class="settings" id="settingsForm" method="dialog">
      <header>
        <h2>Settings</h2>
      </header>
      <section class="settings-grid">
        <label class="wide">Display timezone
          <select id="settingsTimeZone"></select>
        </label>
      </section>
      <section class="settings-grid">
        <h3 class="wide">Log Source</h3>
        <label>Fetch mode
          <select name="sourceMode">
            <option value="http">HTTP bucket listing</option>
            <option value="s3-api">S3 API with IAM credentials</option>
          </select>
        </label>
        <label>AWS region
          <input name="sourceRegion" autocomplete="off" placeholder="us-east-1">
        </label>
        <label class="wide">S3 bucket URL
          <input name="sourceBucketUrl" autocomplete="off" placeholder="https://bucket.s3.us-east-1.amazonaws.com/">
        </label>
        <label>S3 bucket name
          <input name="sourceBucketName" autocomplete="off" placeholder="bucket-name">
        </label>
        <label>Log prefix
          <input name="sourceLogPrefix" autocomplete="off" placeholder="CloudConnexa/wellesley/">
        </label>
        <div class="muted wide" id="sourceCredentialStatus"></div>
      </section>
      <section class="settings-grid">
        <h3 class="wide">SAML 2.0 SSO</h3>
        <label class="check-row"><input type="checkbox" name="enabled"> Enable SAML login</label>
        <label class="check-row"><input type="checkbox" name="requireAuth"> Require SSO for API access</label>
        <label>SP entity ID
          <input name="issuer" autocomplete="off">
        </label>
        <label>SP ACS callback URL
          <input name="callbackUrl" autocomplete="off" placeholder="Auto-generated if blank">
        </label>
        <label>IdP login URL
          <input name="entryPoint" autocomplete="off">
        </label>
        <label>IdP logout URL
          <input name="logoutUrl" autocomplete="off">
        </label>
        <label class="wide">Audience
          <input name="audience" autocomplete="off" placeholder="Defaults to SP entity ID">
        </label>
        <label class="wide">IdP signing certificate
          <textarea name="idpCert" spellcheck="false"></textarea>
        </label>
        <label class="check-row"><input type="checkbox" name="wantAssertionsSigned"> Require signed assertions</label>
        <label class="check-row"><input type="checkbox" name="wantAuthnResponseSigned"> Require signed responses</label>
        <label class="check-row wide"><input type="checkbox" name="disableRequestedAuthnContext"> Let the IdP choose auth context</label>
        <label class="wide">SP metadata URL
          <input id="metadataUrl" readonly>
        </label>
      </section>
      <div class="settings-actions">
        <button type="button" class="secondary" id="closeSettings">Close</button>
        <button type="submit">Save Settings</button>
      </div>
    </form>
  </dialog>
  <script>
    const filters = document.querySelector("#filters");
    const rows = document.querySelector("#rows");
    const eventsTable = document.querySelector("#eventsTable");
    const layout = document.querySelector("#layout");
    const statusEl = document.querySelector("#status");
    const details = document.querySelector("#details");
    const detailPanel = document.querySelector("#detailPanel");
    const churnWatch = document.querySelector("#churnWatch");
    const statsEl = document.querySelector("#stats");
    const connectedChart = document.querySelector("#connectedChart");
    const connectedChartMeta = document.querySelector("#connectedChartMeta");
    const connectedRange = document.querySelector("#connectedRange");
    const sourceLine = document.querySelector("#sourceLine");
    const closeDetail = document.querySelector("#closeDetail");
    const accountMenu = document.querySelector("#accountMenu");
    const accountMenuButton = document.querySelector("#accountMenuButton");
    const accountName = document.querySelector("#accountName");
    const loginLink = document.querySelector("#loginLink");
    const logoutLink = document.querySelector("#logoutLink");
    const settingsButton = document.querySelector("#settingsButton");
    const settingsDialog = document.querySelector("#settingsDialog");
    const settingsForm = document.querySelector("#settingsForm");
    const settingsTimeZone = document.querySelector("#settingsTimeZone");
    const sourceCredentialStatus = document.querySelector("#sourceCredentialStatus");
    const closeSettings = document.querySelector("#closeSettings");
    const metadataUrl = document.querySelector("#metadataUrl");
    const IDLE_RELOAD_MS = 30 * 60 * 1000;
    const TIME_ZONE_STORAGE_KEY = "openvpnLogBrowserTimeZone";
    const COLUMN_WIDTH_STORAGE_KEY = "openvpnLogBrowserColumnWidths";
    const defaultColumnWidths = {
      time: 205,
      user: 210,
      event: 150,
      device: 230,
      ip: 250,
      gateway: 230,
      duration: 105,
      transfer: 110
    };
    const minColumnWidths = {
      time: 150,
      user: 130,
      event: 105,
      device: 150,
      ip: 160,
      gateway: 150,
      duration: 88,
      transfer: 90
    };
    const localTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
    const timeZones = Array.from(new Set([
      localTimeZone,
      "UTC",
      "America/New_York",
      "America/Chicago",
      "America/Denver",
      "America/Los_Angeles",
      "Europe/London"
    ]));
    let selectedTimeZone = validTimeZone(localStorage.getItem(TIME_ZONE_STORAGE_KEY) || localTimeZone);
    if (!timeZones.includes(selectedTimeZone)) timeZones.unshift(selectedTimeZone);
    let selectedRecordId = "";
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
      const prioritized = excessiveCount ? users.filter(user => user.severity === "high" || user.severity === "elevated") : users;
      const rows = prioritized.slice(0, 4);
      if (!rows.length) return '<div class="muted">No excessive reconnect pattern detected.</div>';
      const more = prioritized.length > rows.length ? '<div class="watch-more">+' + esc(prioritized.length - rows.length) + ' more</div>' : "";
      return rows.map(user => '<div class="watch-user ' + esc(user.severity) + '">' +
        '<button type="button" class="watch-user-link" data-user="' + esc(user.userName) + '" title="Search events for ' + esc(user.userName) + '">' + esc(user.userName) + '</button>' +
        '<span>' + esc(user.total) + ' events</span>' +
      '</div>').join("") + more;
    }

    function loadColumnWidths() {
      try {
        return { ...defaultColumnWidths, ...JSON.parse(localStorage.getItem(COLUMN_WIDTH_STORAGE_KEY) || "{}") };
      } catch {
        return { ...defaultColumnWidths };
      }
    }

    function saveColumnWidths(widths) {
      localStorage.setItem(COLUMN_WIDTH_STORAGE_KEY, JSON.stringify(widths));
    }

    function applyColumnWidths(widths = loadColumnWidths()) {
      for (const col of eventsTable.querySelectorAll("col[data-col]")) {
        const key = col.dataset.col;
        const min = minColumnWidths[key] || 80;
        const width = Math.max(min, Number(widths[key] || defaultColumnWidths[key] || min));
        col.style.width = width + "px";
      }
    }

    function setupResizableColumns() {
      applyColumnWidths();
      eventsTable.querySelectorAll("th[data-col]").forEach(th => {
        const handle = th.querySelector(".col-resizer");
        if (!handle) return;
        handle.addEventListener("pointerdown", event => {
          event.preventDefault();
          event.stopPropagation();
          const key = th.dataset.col;
          const widths = loadColumnWidths();
          const startX = event.clientX;
          const startWidth = Number(widths[key] || th.getBoundingClientRect().width || defaultColumnWidths[key]);
          const min = minColumnWidths[key] || 80;
          document.body.classList.add("resizing-columns");
          handle.setPointerCapture(event.pointerId);

          const move = moveEvent => {
            widths[key] = Math.max(min, Math.round(startWidth + moveEvent.clientX - startX));
            applyColumnWidths(widths);
          };
          const up = () => {
            document.body.classList.remove("resizing-columns");
            saveColumnWidths(widths);
            handle.removeEventListener("pointermove", move);
            handle.removeEventListener("pointerup", up);
            handle.removeEventListener("pointercancel", up);
          };

          handle.addEventListener("pointermove", move);
          handle.addEventListener("pointerup", up);
          handle.addEventListener("pointercancel", up);
        });
      });
    }

    async function loadAuth() {
      const data = await getJson("/api/auth");
      accountName.textContent = data.user && data.user.authenticated
        ? (data.user.email || data.user.name || "Signed in")
        : "Not signed in";
      loginLink.style.display = data.saml && data.saml.ready ? "flex" : "none";
      logoutLink.style.display = data.user && data.user.authenticated ? "flex" : "none";
      accountMenuButton.textContent = data.user && data.user.authenticated ? "Account" : "Menu";
      return data;
    }

    async function loadSettings() {
      fillTimeZoneSettings();
      const source = await getJson("/api/settings/source");
      settingsForm.elements.sourceMode.value = source.mode || "http";
      settingsForm.elements.sourceBucketUrl.value = source.bucketUrl || "";
      settingsForm.elements.sourceBucketName.value = source.bucketName || "";
      settingsForm.elements.sourceRegion.value = source.region || "";
      settingsForm.elements.sourceLogPrefix.value = source.logPrefix || "";
      sourceCredentialStatus.textContent = source.mode === "s3-api"
        ? (source.hasIamCredentialEnv ? "IAM credential environment detected." : "IAM credentials are read from the service environment or instance role.")
        : "HTTP mode uses bucket policy access.";
      const saml = await getJson("/api/settings/saml");
      settingsForm.elements.enabled.checked = Boolean(saml.enabled);
      settingsForm.elements.requireAuth.checked = Boolean(saml.requireAuth);
      settingsForm.elements.issuer.value = saml.issuer || "";
      settingsForm.elements.callbackUrl.value = saml.callbackUrl || "";
      settingsForm.elements.entryPoint.value = saml.entryPoint || "";
      settingsForm.elements.logoutUrl.value = saml.logoutUrl || "";
      settingsForm.elements.audience.value = saml.audience || "";
      settingsForm.elements.idpCert.value = saml.idpCert || "";
      settingsForm.elements.wantAssertionsSigned.checked = Boolean(saml.wantAssertionsSigned);
      settingsForm.elements.wantAuthnResponseSigned.checked = Boolean(saml.wantAuthnResponseSigned);
      settingsForm.elements.disableRequestedAuthnContext.checked = Boolean(saml.disableRequestedAuthnContext);
      metadataUrl.value = saml.metadataUrl || "";
    }

    function fillTimeZoneSettings() {
      settingsTimeZone.innerHTML = timeZones.map(zone =>
        '<option value="' + esc(zone) + '"' + (zone === selectedTimeZone ? " selected" : "") + '>' + esc(zoneLabel(zone)) + '</option>'
      ).join("");
    }

    async function saveSettings() {
      selectedTimeZone = validTimeZone(settingsTimeZone.value);
      localStorage.setItem(TIME_ZONE_STORAGE_KEY, selectedTimeZone);
      await getJson("/api/settings/source", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mode: settingsForm.elements.sourceMode.value,
          bucketUrl: settingsForm.elements.sourceBucketUrl.value,
          bucketName: settingsForm.elements.sourceBucketName.value,
          region: settingsForm.elements.sourceRegion.value,
          logPrefix: settingsForm.elements.sourceLogPrefix.value
        })
      });
      await getJson("/api/settings/saml", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled: settingsForm.elements.enabled.checked,
          requireAuth: settingsForm.elements.requireAuth.checked,
          issuer: settingsForm.elements.issuer.value,
          callbackUrl: settingsForm.elements.callbackUrl.value,
          entryPoint: settingsForm.elements.entryPoint.value,
          logoutUrl: settingsForm.elements.logoutUrl.value,
          audience: settingsForm.elements.audience.value,
          idpCert: settingsForm.elements.idpCert.value,
          wantAssertionsSigned: settingsForm.elements.wantAssertionsSigned.checked,
          wantAuthnResponseSigned: settingsForm.elements.wantAuthnResponseSigned.checked,
          disableRequestedAuthnContext: settingsForm.elements.disableRequestedAuthnContext.checked
        })
      });
      settingsDialog.close();
      await loadAuth();
      await loadStats();
      await loadConnectedChart();
      await search();
      if (selectedRecordId) await selectRecord(selectedRecordId);
    }

    async function loadConnectedChart() {
      const data = await getJson("/api/connected-users?range=" + encodeURIComponent(connectedRange.value));
      renderConnectedChart(data);
    }

    function renderConnectedChart(data) {
      const points = data.points || [];
      connectedChartMeta.textContent = points.length
        ? "excluding " + (data.excludedUsers ?? latestExcluded(points)) + " reconnect-heavy users"
        : "No connection data loaded";
      if (!points.length) {
        connectedChart.innerHTML = '<div class="muted">Loading connection trend...</div>';
        return;
      }

      const width = Math.max(340, Math.round(connectedChart.clientWidth || 540));
      const height = 92;
      const pad = { top: 8, right: 10, bottom: 18, left: 26 };
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
      return date.toLocaleString([], { timeZone: selectedTimeZone, month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
    }

    function displayTime(value) {
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value || "";
      return date.toLocaleString([], {
        timeZone: selectedTimeZone,
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
        timeZoneName: "short"
      });
    }

    function validTimeZone(zone) {
      try {
        Intl.DateTimeFormat([], { timeZone: zone }).format(new Date());
        return zone;
      } catch {
        return localTimeZone;
      }
    }

    function fill(name, values) {
      const select = filters.elements[name];
      const current = select.value;
      select.innerHTML = '<option value="">All</option>' + values.map(value => '<option>' + esc(value) + '</option>').join("");
      select.value = current;
    }

    async function loadStats() {
      const data = await getJson("/api/stats?timeZone=" + encodeURIComponent(selectedTimeZone));
      sourceLine.textContent = data.source + " | loaded " + (data.loadedAt ? displayTime(data.loadedAt) : "never");
      statusEl.textContent = data.loading ? "Loading logs..." : (data.error || "");
      statusEl.className = data.error ? "status error" : "status";
      statsEl.innerHTML = [
        stat("Active users", data.activeUsers + " users / " + data.activeSessions + " sessions")
      ].join("");
      scheduleLoadingPoll(data.loading);
      return data;
    }

    function stat(label, value) {
      return '<div class="stat"><strong>' + esc(value) + '</strong><span>' + esc(label) + '</span></div>';
    }

    function zoneLabel(zone) {
      return zone === localTimeZone ? "Local (" + zone + ")" : zone;
    }

    async function search() {
      const data = await getJson("/api/search?" + params());
      statusEl.textContent = (statusEl.className.includes("error") ? statusEl.textContent + " | " : "") + "searched " + data.searched + " loaded events; " + data.total + " matched; showing " + data.rows.length + " of " + data.limit;
      rows.innerHTML = data.rows.map(record => '<tr data-id="' + esc(record.id) + '"' + (record.id === selectedRecordId ? ' class="selected"' : "") + '>' +
        '<td class="time">' + esc(displayTime(record.timestamp)) + '</td>' +
        '<td class="user wrap">' + esc(record.userName || record.initiatorName) + '</td>' +
        '<td><span class="chip">' + esc(record.eventName || record.operation || "event") + '</span></td>' +
        '<td class="wrap">' + esc(record.deviceName || record.entityName) + '<br><span class="muted">' + esc(record.os) + '</span></td>' +
        '<td class="ip wrap">' + esc(record.publicIp) + '<br><span class="muted">' + esc(record.tunnelIp) + '</span></td>' +
        '<td class="wrap">' + esc(record.gateway || record.gatewayRegion) + '<br><span class="muted">' + esc(record.protocol) + '</span></td>' +
        '<td>' + esc(formatDuration(record.durationSeconds)) + '</td>' +
        '<td>' + esc(formatBytes((record.bytesIn || 0) + (record.bytesOut || 0))) + '</td>' +
      '</tr>').join("");
      highlightSelectedRow();
    }

    async function selectRecord(id) {
      selectedRecordId = id;
      const record = await getJson("/api/record?id=" + encodeURIComponent(id));
      detailPanel.hidden = false;
      layout.classList.add("detail-open");
      closeDetail.style.display = "inline-flex";
      details.innerHTML = '<div class="kv">' +
        kv("Timestamp", displayTime(record.timestamp)) +
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
      highlightSelectedRow();
    }

    function clearSelectedRecord() {
      selectedRecordId = "";
      detailPanel.hidden = true;
      layout.classList.remove("detail-open");
      closeDetail.style.display = "none";
      details.textContent = "";
      highlightSelectedRow();
    }

    function highlightSelectedRow() {
      for (const tr of rows.querySelectorAll("tr")) {
        tr.classList.toggle("selected", Boolean(selectedRecordId) && tr.dataset.id === selectedRecordId);
      }
    }

    function kv(key, value) {
      return '<div>' + esc(key) + '</div><div>' + esc(value || "-") + '</div>';
    }

    function churnPanel(churn) {
      if (!churn) return "";
      const recent = (churn.latest || []).map(item => '<div>' +
        esc(displayTime(item.timestamp)) + " | " +
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
      clearSelectedRecord();
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
    churnWatch.addEventListener("click", event => {
      const link = event.target.closest(".watch-user-link");
      if (!link) return;
      filters.elements.q.value = link.dataset.user || "";
      search().catch(showError);
    });
    rows.addEventListener("click", event => {
      const tr = event.target.closest("tr");
      if (!tr) return;
      if (tr.dataset.id === selectedRecordId) {
        clearSelectedRecord();
      } else {
        selectRecord(tr.dataset.id).catch(showError);
      }
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
    accountMenuButton.addEventListener("click", () => {
      const open = !accountMenu.classList.contains("open");
      accountMenu.classList.toggle("open", open);
      accountMenuButton.setAttribute("aria-expanded", String(open));
    });
    document.addEventListener("click", (event) => {
      if (!accountMenu.contains(event.target)) {
        accountMenu.classList.remove("open");
        accountMenuButton.setAttribute("aria-expanded", "false");
      }
    });
    settingsButton.addEventListener("click", async () => {
      accountMenu.classList.remove("open");
      await loadSettings();
      settingsDialog.showModal();
    });
    closeSettings.addEventListener("click", () => settingsDialog.close());
    settingsForm.addEventListener("submit", (event) => {
      event.preventDefault();
      saveSettings().catch(showError);
    });

    function showError(error) {
      statusEl.textContent = error.message;
      statusEl.className = "status error";
    }

    async function boot() {
      await loadAuth();
      applyColumnWidths();
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

    setupResizableColumns();
    boot().catch(showError);
  </script>
</body>
</html>`;

if (process.argv.includes("--ingest")) {
  Promise.all([loadSamlSettings(), loadSourceSettings()]).then(() => refresh()).then(() => {
    console.log(JSON.stringify(stats(), null, 2));
  }).catch((error) => {
    console.error(error);
    process.exit(1);
  });
} else {
  http.createServer(handler).listen(PORT, () => {
    console.log(`OpenVPN Log Search listening on http://localhost:${PORT}`);
    Promise.all([loadSamlSettings(), loadSourceSettings()]).then(() =>
      initMysql().catch((error) => {
        mysqlStatus = `unavailable: ${error.message}`;
        console.error(error);
      })
    ).catch(console.error).finally(() => refresh().catch((error) => {
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
