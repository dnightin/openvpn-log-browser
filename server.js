const http = require("node:http");
const https = require("node:https");
const fs = require("node:fs/promises");
const fsSync = require("node:fs");
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
const LOG_INDEX_RETENTION_DAYS = Math.max(0, Number(process.env.LOG_INDEX_RETENTION_DAYS || 0));
const SLOW_API_MS = Math.max(0, Number(process.env.SLOW_API_MS || 500));
const SLOW_DB_MS = Math.max(0, Number(process.env.SLOW_DB_MS || 500));
const SESSION_COOKIE = "openvpn_log_browser_session";
const SESSION_IDLE_TIMEOUT_MS = Math.max(1, Number(process.env.SESSION_IDLE_TIMEOUT_MINUTES || 720)) * 60 * 1000;
const TRUST_PROXY = toBool(process.env.TRUST_PROXY);
const ADMIN_EMAILS = String(process.env.ADMIN_EMAILS || "")
  .split(",")
  .map((value) => value.trim().toLowerCase())
  .filter(Boolean);
const ADMIN_SETUP_TOKEN = process.env.ADMIN_SETUP_TOKEN || "";
const MYSQL_ENABLED = Boolean(process.env.MYSQL_HOST || process.env.MYSQL_USER || process.env.MYSQL_DATABASE);
const MYSQL_CONFIG = {
  host: process.env.MYSQL_HOST || "127.0.0.1",
  port: Number(process.env.MYSQL_PORT || 3306),
  user: process.env.MYSQL_USER || "openvpn_log_browser",
  password: process.env.MYSQL_PASSWORD || "",
  database: process.env.MYSQL_DATABASE || "openvpn_log_browser"
};
const WEB_INGEST_ENABLED = process.env.WEB_INGEST_ENABLED ? toBool(process.env.WEB_INGEST_ENABLED) : !MYSQL_ENABLED;
const SECRET_KEY_RE = /(token|secret|password|passwd|credential|privatekey|clientkey|apikey|authorization|cookie|bearer)/i;

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
let mysqlLogIndexReady = false;
let mysqlFullTextReady = false;
let samlSettings = envSamlSettings();
let sourceSettings = null;
let objectRecordCache = new Map();
let objectRecordCacheSource = "";
let slowEvents = [];
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

function requestProtocol(req) {
  if (TRUST_PROXY) {
    const forwarded = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
    if (forwarded) return forwarded;
  }
  return req.socket && req.socket.encrypted ? "https" : "http";
}

function isSecureRequest(req) {
  return requestProtocol(req) === "https";
}

function requestOrigin(req) {
  return `${requestProtocol(req)}://${req.headers.host || `localhost:${PORT}`}`;
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
  if (Date.now() - session.lastSeen > SESSION_IDLE_TIMEOUT_MS) {
    sessions.delete(sessionId);
    return { authenticated: false, name: "", email: "", source: "none" };
  }
  session.lastSeen = Date.now();
  return { authenticated: true, ...session.user };
}

function sweepExpiredSessions() {
  const now = Date.now();
  for (const [sessionId, session] of sessions) {
    if (now - session.lastSeen > SESSION_IDLE_TIMEOUT_MS) sessions.delete(sessionId);
  }
}

function createSession(req, res, profile = {}) {
  const sessionId = crypto.randomBytes(32).toString("base64url");
  const user = {
    name: profile.displayName || profile.name || profile.cn || profile.email || profile.nameID || "SAML user",
    email: profile.email || profile.mail || profile.nameID || "",
    source: "saml"
  };
  sessions.set(sessionId, { user, createdAt: Date.now(), lastSeen: Date.now() });
  setCookie(res, SESSION_COOKIE, sessionId, { httpOnly: true, sameSite: "Lax", path: "/", secure: isSecureRequest(req) });
  return user;
}

function clearSession(req, res) {
  const cookies = parseCookies(req.headers.cookie || "");
  if (cookies[SESSION_COOKIE]) sessions.delete(cookies[SESSION_COOKIE]);
  setCookie(res, SESSION_COOKIE, "", { maxAge: 0, httpOnly: true, sameSite: "Lax", path: "/", secure: isSecureRequest(req) });
}

function adminConfigured() {
  return Boolean(ADMIN_SETUP_TOKEN || ADMIN_EMAILS.length);
}

function bearerToken(req) {
  const header = req.headers.authorization || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : "";
}

function timingSafeEqualString(a, b) {
  const bufA = Buffer.from(String(a || ""));
  const bufB = Buffer.from(String(b || ""));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function isAdminRequest(req) {
  if (ADMIN_SETUP_TOKEN) {
    const provided = req.headers["x-admin-token"] || bearerToken(req);
    if (provided && timingSafeEqualString(provided, ADMIN_SETUP_TOKEN)) return true;
  }
  if (ADMIN_EMAILS.length) {
    const user = currentUser(req);
    if (user.authenticated && user.email && ADMIN_EMAILS.includes(user.email.toLowerCase())) return true;
  }
  return false;
}

function requireAdmin(req, res) {
  if (!adminConfigured()) {
    json(res, { error: "Admin access is not configured. Set ADMIN_SETUP_TOKEN or ADMIN_EMAILS to allow settings changes." }, 403);
    return false;
  }
  if (!isAdminRequest(req)) {
    json(res, { error: "Admin access required." }, 403);
    return false;
  }
  return true;
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
  if (options.secure) parts.push("Secure");
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
  createSession(req, res, result.profile || result);
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

function httpGetBufferOnce(url, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith("https:") ? https : http;
    const req = client.get(url, { timeout: 30000 }, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        if (redirectsLeft <= 0) {
          reject(new Error(`GET ${url} exceeded maximum redirects`));
          return;
        }
        resolve(httpGetBufferOnce(new URL(res.headers.location, url).toString(), redirectsLeft - 1));
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

async function loadFromS3() {
  const config = sourceConfig();
  const apiMode = config.mode === "s3-api";
  const sourceId = sourceCacheId(config);
  const sourceHash = hashId(sourceId);
  if (objectRecordCacheSource !== sourceId) {
    objectRecordCache = new Map();
    objectRecordCacheSource = sourceId;
  }
  const objects = apiMode ? await listBucketObjectsApi(config) : await listBucketObjectsHttp(config);
  const client = apiMode ? await s3Client(config) : null;
  const manifest = await loadS3CacheManifest(sourceId);
  const mysqlIndex = await mysqlIndexedObjects(sourceHash);
  const records = [];
  const failed = [];
  const pending = [];
  const seenKeys = new Set();
  let reusedMemory = 0;
  let reusedDisk = 0;
  let reusedMysql = 0;
  let downloaded = 0;
  let batchesSinceManifestSave = 0;

  for (const object of objects) {
    seenKeys.add(object.key);
    const fingerprint = objectFingerprint(object);
    const cached = objectRecordCache.get(object.key);
    if (cached && cached.fingerprint === fingerprint) {
      if (!mysqlIndex) records.push(...cached.records);
      reusedMemory += 1;
    } else if (mysqlIndex && mysqlIndex.get(object.key) === fingerprint) {
      reusedMysql += 1;
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
  pending.sort((a, b) => cachePriority(manifest, b) - cachePriority(manifest, a));

  for (let index = 0; index < pending.length; index += FETCH_CONCURRENCY) {
    const batch = pending.slice(index, index + FETCH_CONCURRENCY);
    const batchResults = await Promise.all(batch.map(async (object) => {
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
        const parsed = await parseJsonlGz(compressed, object.key);
        objectRecordCache.set(object.key, { fingerprint: object.fingerprint, records: parsed });
        return { object, records: parsed, indexable: true };
      } catch (error) {
        if (cached) {
          failed.push(`${object.key}: ${error.message}; used cached records`);
          return { object, records: cached.records, indexable: false };
        }
        failed.push(`${object.key}: ${error.message}`);
        return { object, records: [], indexable: false };
      }
    }));
    await saveParsedObjectsToMysql(sourceId, sourceHash, batchResults.filter((result) => result.indexable));
    if (!mysqlIndex) {
      for (const result of batchResults) records.push(...result.records);
    }
    store = {
      ...store,
      records,
      source: apiMode ? `s3://${config.bucketName}/${config.logPrefix}` : config.bucketUrl,
      objects,
      error: `Loading S3 objects ${Math.min(index + batch.length, pending.length)} of ${pending.length} not indexed; mysql ${reusedMysql}, memory ${reusedMemory}, disk ${reusedDisk}, downloaded ${downloaded}.`
    };
    batchesSinceManifestSave += 1;
    if (batchesSinceManifestSave >= 25) {
      await saveS3CacheManifest(manifest, seenKeys);
      batchesSinceManifestSave = 0;
    }
    await yieldToEventLoop(LOAD_BATCH_DELAY_MS);
  }
  await saveS3CacheManifest(manifest, seenKeys);
  await pruneLogIndexRetention(sourceHash);
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

function cachePriority(manifest, object) {
  const entry = manifest.objects[object.key];
  if (!entry) return 0;
  return entry.fingerprint === object.fingerprint ? 2 : 1;
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
    records.push(...await parseJsonlGz(compressed, key));
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
  await mysqlPool.query(`
    CREATE TABLE IF NOT EXISTS log_s3_objects (
      source_hash CHAR(64) NOT NULL,
      object_hash CHAR(64) NOT NULL,
      source_id TEXT NOT NULL,
      object_key TEXT NOT NULL,
      fingerprint VARCHAR(255) NOT NULL,
      etag VARCHAR(128) NOT NULL DEFAULT '',
      size BIGINT UNSIGNED NOT NULL DEFAULT 0,
      last_modified DATETIME NULL,
      parsed_at DATETIME NOT NULL,
      record_count INT UNSIGNED NOT NULL DEFAULT 0,
      PRIMARY KEY (source_hash, object_hash),
      KEY parsed_at_idx (parsed_at)
    )
  `);
  await mysqlPool.query(`
    CREATE TABLE IF NOT EXISTS log_events (
      id_hash CHAR(64) NOT NULL PRIMARY KEY,
      source_hash CHAR(64) NOT NULL,
      object_hash CHAR(64) NOT NULL,
      id TEXT NOT NULL,
      source_key TEXT NOT NULL,
      line_number INT UNSIGNED NOT NULL,
      timestamp_dt DATETIME NULL,
      timestamp_text VARCHAR(64) NOT NULL DEFAULT '',
      date_text VARCHAR(16) NOT NULL DEFAULT '',
      category VARCHAR(128) NOT NULL DEFAULT '',
      event_name VARCHAR(128) NOT NULL DEFAULT '',
      initiator VARCHAR(255) NOT NULL DEFAULT '',
      initiator_name VARCHAR(255) NOT NULL DEFAULT '',
      user_name VARCHAR(255) NOT NULL DEFAULT '',
      device_name VARCHAR(255) NOT NULL DEFAULT '',
      initiator_type VARCHAR(128) NOT NULL DEFAULT '',
      public_ip VARCHAR(128) NOT NULL DEFAULT '',
      operation_name VARCHAR(128) NOT NULL DEFAULT '',
      entity_type VARCHAR(128) NOT NULL DEFAULT '',
      entity_name VARCHAR(255) NOT NULL DEFAULT '',
      parent_entity_name VARCHAR(255) NOT NULL DEFAULT '',
      session_id VARCHAR(128) NOT NULL DEFAULT '',
      protocol_name VARCHAR(128) NOT NULL DEFAULT '',
      gateway VARCHAR(255) NOT NULL DEFAULT '',
      gateway_region VARCHAR(128) NOT NULL DEFAULT '',
      os VARCHAR(255) NOT NULL DEFAULT '',
      tunnel_ip VARCHAR(255) NOT NULL DEFAULT '',
      tunnel_ip_v4 VARCHAR(128) NOT NULL DEFAULT '',
      tunnel_ip_v6 VARCHAR(128) NOT NULL DEFAULT '',
      session_start_time VARCHAR(64) NOT NULL DEFAULT '',
      session_end_time VARCHAR(64) NOT NULL DEFAULT '',
      duration_seconds INT UNSIGNED NOT NULL DEFAULT 0,
      bytes_in BIGINT UNSIGNED NOT NULL DEFAULT 0,
      bytes_out BIGINT UNSIGNED NOT NULL DEFAULT 0,
      disconnect_reason VARCHAR(255) NOT NULL DEFAULT '',
      trace_id VARCHAR(128) NOT NULL DEFAULT '',
      user_agent TEXT NOT NULL,
      search_text LONGTEXT NOT NULL,
      raw_json LONGTEXT NOT NULL,
      KEY source_object_idx (source_hash, object_hash),
      KEY timestamp_idx (timestamp_dt),
      KEY event_idx (event_name),
      KEY category_idx (category),
      KEY user_idx (user_name),
      KEY public_ip_idx (public_ip),
      KEY session_idx (session_id)
    )
  `);
  await mysqlPool.query(`
    CREATE TABLE IF NOT EXISTS log_stats_cache (
      source_hash CHAR(64) NOT NULL PRIMARY KEY,
      records BIGINT UNSIGNED NOT NULL DEFAULT 0,
      objects BIGINT UNSIGNED NOT NULL DEFAULT 0,
      active_sessions INT UNSIGNED NOT NULL DEFAULT 0,
      active_users INT UNSIGNED NOT NULL DEFAULT 0,
      first_timestamp VARCHAR(64) NOT NULL DEFAULT '',
      last_timestamp VARCHAR(64) NOT NULL DEFAULT '',
      total_bytes_in BIGINT UNSIGNED NOT NULL DEFAULT 0,
      total_bytes_out BIGINT UNSIGNED NOT NULL DEFAULT 0,
      by_event_json LONGTEXT NOT NULL,
      by_day_json LONGTEXT NOT NULL,
      generated_at DATETIME NOT NULL
    )
  `);
  await mysqlPool.query(`
    CREATE TABLE IF NOT EXISTS active_sessions_snapshot (
      source_hash CHAR(64) NOT NULL,
      user_name VARCHAR(255) NOT NULL,
      session_id VARCHAR(128) NOT NULL DEFAULT '',
      event_timestamp DATETIME NULL,
      timestamp_text VARCHAR(64) NOT NULL DEFAULT '',
      generated_at DATETIME NOT NULL,
      PRIMARY KEY (source_hash, user_name),
      KEY generated_at_idx (generated_at)
    )
  `);
  await mysqlPool.query(`
    CREATE TABLE IF NOT EXISTS log_facets_cache (
      source_hash CHAR(64) NOT NULL PRIMARY KEY,
      categories_json LONGTEXT NOT NULL,
      event_names_json LONGTEXT NOT NULL,
      operating_systems_json LONGTEXT NOT NULL,
      gateways_json LONGTEXT NOT NULL,
      users_json LONGTEXT NOT NULL,
      ips_json LONGTEXT NOT NULL,
      generated_at DATETIME NOT NULL
    )
  `);
  await mysqlPool.query(`
    CREATE TABLE IF NOT EXISTS churn_watch_cache (
      source_hash CHAR(64) NOT NULL PRIMARY KEY,
      payload_json LONGTEXT NOT NULL,
      generated_at DATETIME NOT NULL
    )
  `);
  await ensureMysqlLogIndexes();
  mysqlLogIndexReady = true;
  const sourceHash = hashId(sourceCacheId(sourceConfig()));
  const indexedObjects = await loadIndexedObjectsFromMysql(sourceHash);
  store = {
    ...store,
    records: [],
    objects: indexedObjects,
    source: indexedObjects.length ? "MariaDB log index" : store.source,
    loadedAt: indexedObjects.length ? new Date().toISOString() : store.loadedAt,
    error: indexedObjects.length ? null : store.error
  };
  mysqlStatus = "connected";
}

async function ensureMysqlLogIndexes() {
  mysqlFullTextReady = await mysqlIndexExists("log_events", "search_text_ft");
  if (!mysqlFullTextReady) {
    await ignoreMysqlIndexError(async () => {
      await mysqlPool.query("ALTER TABLE log_events ADD FULLTEXT INDEX search_text_ft (search_text)");
      mysqlFullTextReady = true;
    });
  }
  mysqlFullTextReady = mysqlFullTextReady || await mysqlIndexExists("log_events", "search_text_ft");
  if (!await mysqlIndexExists("log_s3_objects", "last_modified_idx")) {
    await ignoreMysqlIndexError(() => mysqlPool.query("ALTER TABLE log_s3_objects ADD KEY last_modified_idx (last_modified)"));
  }
  await ensureMysqlIndex("log_events", "source_time_idx", "ALTER TABLE log_events ADD KEY source_time_idx (source_hash, timestamp_dt)");
  await ensureMysqlIndex("log_events", "source_event_time_idx", "ALTER TABLE log_events ADD KEY source_event_time_idx (source_hash, event_name, timestamp_dt)");
  await ensureMysqlIndex("log_events", "source_user_time_idx", "ALTER TABLE log_events ADD KEY source_user_time_idx (source_hash, user_name, timestamp_dt)");
  await ensureMysqlIndex("log_events", "source_category_time_idx", "ALTER TABLE log_events ADD KEY source_category_time_idx (source_hash, category, timestamp_dt)");
}

async function ensureMysqlIndex(tableName, indexName, statement) {
  if (!await mysqlIndexExists(tableName, indexName)) {
    await ignoreMysqlIndexError(() => mysqlPool.query(statement));
  }
}

async function mysqlIndexExists(tableName, indexName) {
  const [rows] = await mysqlPool.execute(
    `SELECT COUNT(*) AS count
     FROM information_schema.statistics
     WHERE table_schema = DATABASE()
       AND table_name = ?
       AND index_name = ?`,
    [tableName, indexName]
  );
  return Number(rows[0]?.count || 0) > 0;
}

async function ignoreMysqlIndexError(operation) {
  try {
    await operation();
  } catch (error) {
    if (error && (error.code === "ER_DUP_KEYNAME" || error.errno === 1061)) return;
    if (error && (error.code === "ER_TABLEACCESS_DENIED_ERROR" || error.errno === 1142)) {
      console.error(`Skipping optional MariaDB index creation: ${error.message}`);
      return;
    }
    throw error;
  }
}

async function timedMysqlExecute(label, sql, values = []) {
  const start = Date.now();
  try {
    return await mysqlPool.execute(sql, values);
  } finally {
    logSlow("db", label, Date.now() - start);
  }
}

async function timedMysqlQuery(label, sql, values = []) {
  const start = Date.now();
  try {
    return await mysqlPool.query(sql, values);
  } finally {
    logSlow("db", label, Date.now() - start);
  }
}

function logSlow(kind, label, elapsedMs) {
  const threshold = kind === "api" ? SLOW_API_MS : SLOW_DB_MS;
  if (threshold && elapsedMs >= threshold) {
    const event = { timestamp: new Date().toISOString(), kind: "slow-" + kind, label, elapsedMs };
    slowEvents.push(event);
    if (slowEvents.length > 50) slowEvents = slowEvents.slice(-50);
    console.warn(JSON.stringify(event));
  }
}

async function saveConnectedCountSample() {
  if (!mysqlPool) return;
  try {
    const snapshot = mysqlLogIndexReady ? await connectedUsersSnapshotFromMysql() : connectedUsersSnapshot();
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

async function pruneLogIndexRetention(sourceHash) {
  if (!mysqlPool || !mysqlLogIndexReady || !LOG_INDEX_RETENTION_DAYS) return;
  await mysqlPool.execute(
    `DELETE e FROM log_events e
     JOIN log_s3_objects o
       ON o.source_hash = e.source_hash AND o.object_hash = e.object_hash
     WHERE e.source_hash = ?
       AND o.last_modified < UTC_TIMESTAMP() - INTERVAL ? DAY`,
    [sourceHash, LOG_INDEX_RETENTION_DAYS]
  );
  await mysqlPool.execute(
    `DELETE FROM log_s3_objects
     WHERE source_hash = ?
       AND last_modified < UTC_TIMESTAMP() - INTERVAL ? DAY`,
    [sourceHash, LOG_INDEX_RETENTION_DAYS]
  );
}

function mysqlDate(date) {
  return date.toISOString().slice(0, 19).replace("T", " ");
}

function mysqlDateOrNull(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : mysqlDate(date);
}

function hashId(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex");
}

function currentSourceHash() {
  return hashId(sourceCacheId(sourceConfig()));
}

function mysqlLogIndexAvailable() {
  return Boolean(mysqlPool && mysqlLogIndexReady);
}

async function mysqlIndexedObjects(sourceHash) {
  if (!mysqlPool || !mysqlLogIndexReady) return null;
  const [rows] = await mysqlPool.execute(
    "SELECT object_key, fingerprint FROM log_s3_objects WHERE source_hash = ?",
    [sourceHash]
  );
  return new Map(rows.map((row) => [row.object_key, row.fingerprint]));
}

async function saveParsedObjectsToMysql(sourceId, sourceHash, parsedObjects) {
  if (!mysqlPool || !mysqlLogIndexReady) return;
  const indexable = parsedObjects.filter((item) => item && item.object);
  if (!indexable.length) return;
  const connection = await mysqlPool.getConnection();
  try {
    await connection.beginTransaction();
    const objectHashes = indexable.map((item) => hashId(item.object.key));
    await connection.query(
      `DELETE FROM log_events WHERE source_hash = ? AND object_hash IN (${objectHashes.map(() => "?").join(",")})`,
      [sourceHash, ...objectHashes]
    );

    const columns = [
      "id_hash", "source_hash", "object_hash", "id", "source_key", "line_number", "timestamp_dt", "timestamp_text",
      "date_text", "category", "event_name", "initiator", "initiator_name", "user_name", "device_name",
      "initiator_type", "public_ip", "operation_name", "entity_type", "entity_name", "parent_entity_name",
      "session_id", "protocol_name", "gateway", "gateway_region", "os", "tunnel_ip", "tunnel_ip_v4", "tunnel_ip_v6",
      "session_start_time", "session_end_time", "duration_seconds", "bytes_in", "bytes_out", "disconnect_reason",
      "trace_id", "user_agent", "search_text", "raw_json"
    ];
    const eventRows = [];
    for (let itemIndex = 0; itemIndex < indexable.length; itemIndex += 1) {
      const item = indexable[itemIndex];
      const objectHash = objectHashes[itemIndex];
      for (const record of item.records || []) eventRows.push(recordToMysqlValues(sourceHash, objectHash, record));
    }
    if (eventRows.length) {
      for (let index = 0; index < eventRows.length; index += 500) {
        const batch = eventRows.slice(index, index + 500);
        const placeholders = batch.map(() => `(${columns.map(() => "?").join(",")})`).join(",");
        await connection.query(
          `INSERT INTO log_events (${columns.join(",")}) VALUES ${placeholders}`,
          batch.flat()
        );
      }
    }

    const objectRows = indexable.map((item, index) => {
      const object = item.object;
      return [
        sourceHash,
        objectHashes[index],
        sourceId,
        object.key,
        object.fingerprint,
        object.etag || "",
        Number(object.size || 0),
        mysqlDateOrNull(object.lastModified),
        (item.records || []).length
      ];
    });
    const objectPlaceholders = objectRows.map(() => "(?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(), ?)").join(",");
    await connection.query(
      `INSERT INTO log_s3_objects
       (source_hash, object_hash, source_id, object_key, fingerprint, etag, size, last_modified, parsed_at, record_count)
       VALUES ${objectPlaceholders}
       ON DUPLICATE KEY UPDATE
         source_id = VALUES(source_id),
         object_key = VALUES(object_key),
         fingerprint = VALUES(fingerprint),
         etag = VALUES(etag),
         size = VALUES(size),
         last_modified = VALUES(last_modified),
         parsed_at = VALUES(parsed_at),
         record_count = VALUES(record_count)`,
      objectRows.flat()
    );
    await connection.commit();
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

function recordToMysqlValues(sourceHash, objectHash, record) {
  return [
    hashId(record.id),
    sourceHash,
    objectHash,
    record.id,
    record.sourceKey,
    Number(record.lineNumber || 0),
    mysqlDateOrNull(record.timestamp),
    record.timestamp || "",
    record.date || "",
    record.category || "",
    record.eventName || "",
    record.initiator || "",
    record.initiatorName || "",
    record.userName || "",
    record.deviceName || "",
    record.initiatorType || "",
    record.publicIp || "",
    record.operation || "",
    record.entityType || "",
    record.entityName || "",
    record.parentEntityName || "",
    record.sessionId || "",
    record.protocol || "",
    record.gateway || "",
    record.gatewayRegion || "",
    record.os || "",
    record.tunnelIp || "",
    record.tunnelIpV4 || "",
    record.tunnelIpV6 || "",
    record.sessionStartTime || "",
    record.sessionEndTime || "",
    Number(record.durationSeconds || 0),
    Number(record.bytesIn || 0),
    Number(record.bytesOut || 0),
    record.disconnectReason || "",
    record.traceId || "",
    record.userAgent || "",
    record.searchText || "",
    JSON.stringify(record.raw || {})
  ];
}

async function loadEventsFromMysql(sourceHash) {
  if (!mysqlPool || !mysqlLogIndexReady) return [];
  const [rows] = await mysqlPool.execute(
    `SELECT id, source_key, line_number, timestamp_text, date_text, category, event_name,
            initiator, initiator_name, user_name, device_name, initiator_type, public_ip,
            operation_name, entity_type, entity_name, parent_entity_name, session_id,
            protocol_name, gateway, gateway_region, os, tunnel_ip, tunnel_ip_v4, tunnel_ip_v6,
            session_start_time, session_end_time, duration_seconds, bytes_in, bytes_out,
            disconnect_reason, trace_id, user_agent, search_text
     FROM log_events
     WHERE source_hash = ?
     ORDER BY timestamp_dt DESC, id_hash DESC`,
    [sourceHash]
  );
  return rows.map(mysqlRowToRecord);
}

async function loadRecordRawFromMysql(sourceHash, id) {
  if (!mysqlPool || !mysqlLogIndexReady) return null;
  const [rows] = await mysqlPool.execute(
    "SELECT raw_json FROM log_events WHERE source_hash = ? AND id_hash = ? LIMIT 1",
    [sourceHash, hashId(id)]
  );
  if (!rows.length) return null;
  try {
    return JSON.parse(rows[0].raw_json || "{}");
  } catch {
    return { parseError: "Stored raw JSON could not be parsed." };
  }
}

async function loadIndexedObjectsFromMysql(sourceHash) {
  if (!mysqlPool || !mysqlLogIndexReady) return [];
  const [rows] = await mysqlPool.execute(
    `SELECT object_key, size, last_modified, etag
     FROM log_s3_objects
     WHERE source_hash = ?
     ORDER BY last_modified DESC, object_key DESC`,
    [sourceHash]
  );
  return rows.map((row) => ({
    key: row.object_key,
    size: Number(row.size || 0),
    lastModified: row.last_modified ? new Date(row.last_modified).toISOString() : "",
    etag: row.etag || ""
  }));
}

function mysqlRowToRecord(row) {
  let raw = {};
  if (row.raw_json) {
    try {
      raw = JSON.parse(row.raw_json || "{}");
    } catch {
      raw = { parseError: "Stored raw JSON could not be parsed." };
    }
  }
  return {
    id: row.id,
    sourceKey: row.source_key,
    lineNumber: Number(row.line_number || 0),
    timestamp: row.timestamp_text || "",
    date: row.date_text || "",
    category: row.category || "",
    eventName: row.event_name || "",
    initiator: row.initiator || "",
    initiatorName: row.initiator_name || "",
    userName: row.user_name || "",
    deviceName: row.device_name || "",
    initiatorType: row.initiator_type || "",
    publicIp: row.public_ip || "",
    operation: row.operation_name || "",
    entityType: row.entity_type || "",
    entityName: row.entity_name || "",
    parentEntityName: row.parent_entity_name || "",
    sessionId: row.session_id || "",
    protocol: row.protocol_name || "",
    gateway: row.gateway || "",
    gatewayRegion: row.gateway_region || "",
    os: row.os || "",
    tunnelIp: row.tunnel_ip || "",
    tunnelIpV4: row.tunnel_ip_v4 || "",
    tunnelIpV6: row.tunnel_ip_v6 || "",
    sessionStartTime: row.session_start_time || "",
    sessionEndTime: row.session_end_time || "",
    durationSeconds: Number(row.duration_seconds || 0),
    bytesIn: Number(row.bytes_in || 0),
    bytesOut: Number(row.bytes_out || 0),
    disconnectReason: row.disconnect_reason || "",
    traceId: row.trace_id || "",
    userAgent: row.user_agent || "",
    raw,
    searchText: row.search_text || ""
  };
}

function mysqlRecordSelect(includeRaw = false) {
  const includeSearch = includeRaw;
  return `SELECT id, source_key, line_number, timestamp_text, date_text, category, event_name,
                 initiator, initiator_name, user_name, device_name, initiator_type, public_ip,
                 operation_name, entity_type, entity_name, parent_entity_name, session_id,
                 protocol_name, gateway, gateway_region, os, tunnel_ip, tunnel_ip_v4, tunnel_ip_v6,
                 session_start_time, session_end_time, duration_seconds, bytes_in, bytes_out,
                 disconnect_reason, trace_id, user_agent${includeSearch ? ", search_text" : ""}${includeRaw ? ", raw_json" : ""}
          FROM log_events`;
}

function mysqlSearchWhere(params, sourceHash, fieldMatch = null) {
  const where = ["source_hash = ?"];
  const values = [sourceHash];
  const q = (params.get("q") || "").trim().toLowerCase();
  const category = params.get("category") || "";
  const eventName = params.get("eventName") || "";
  const os = params.get("os") || "";
  const gateway = params.get("gateway") || "";
  const start = params.get("start") || "";
  const end = params.get("end") || "";
  if (q) {
    if (fieldMatch) {
      where.push(`${fieldMatch.column} = ?`);
      values.push(fieldMatch.value);
    } else if (mysqlFullTextReady) {
      where.push("MATCH(search_text) AGAINST (? IN BOOLEAN MODE)");
      values.push(mysqlBooleanSearchQuery(q));
    } else {
      where.push("search_text LIKE ?");
      values.push(`%${q}%`);
    }
  }
  if (category) {
    where.push("category = ?");
    values.push(category);
  }
  if (eventName) {
    where.push("event_name = ?");
    values.push(eventName);
  }
  if (os) {
    where.push("os LIKE ?");
    values.push(`${os}%`);
  }
  if (gateway) {
    where.push("gateway LIKE ?");
    values.push(`%${gateway}%`);
  }
  if (start) {
    const startDate = mysqlDateOrNull(start);
    if (startDate) {
      where.push("timestamp_dt >= ?");
      values.push(startDate);
    } else {
      where.push("timestamp_text >= ?");
      values.push(start);
    }
  }
  if (end) {
    const endDate = mysqlDateOrNull(end);
    if (endDate) {
      where.push("timestamp_dt <= ?");
      values.push(endDate);
    } else {
      where.push("timestamp_text <= ?");
      values.push(end);
    }
  }
  return { sql: where.join(" AND "), values };
}

function mysqlCursorWhere(params) {
  const cursor = decodeSearchCursor(params.get("cursor") || "");
  if (!cursor) return { sql: "", values: [], cursor: null };
  const cursorDate = mysqlDateOrNull(cursor.timestamp);
  if (!cursorDate || !cursor.idHash) return { sql: "", values: [], cursor: null };
  return {
    sql: " AND (timestamp_dt < ? OR (timestamp_dt = ? AND id_hash < ?))",
    values: [cursorDate, cursorDate, cursor.idHash],
    cursor
  };
}

function decodeSearchCursor(value) {
  if (!value) return null;
  try {
    const decoded = JSON.parse(Buffer.from(String(value), "base64url").toString("utf8"));
    if (!decoded || typeof decoded !== "object") return null;
    return {
      timestamp: String(decoded.timestamp || ""),
      idHash: String(decoded.idHash || "")
    };
  } catch {
    return null;
  }
}

function encodeSearchCursor(record) {
  if (!record || !record.timestamp || !record.id) return "";
  return Buffer.from(JSON.stringify({
    timestamp: record.timestamp,
    idHash: hashId(record.id)
  })).toString("base64url");
}

function mysqlBooleanSearchQuery(value) {
  const terms = String(value || "")
    .toLowerCase()
    .match(/[a-z0-9@._:-]+/g);
  if (!terms || !terms.length) return "";
  return terms.slice(0, 12).map((term) => `+${term}${term.length >= 3 ? "*" : ""}`).join(" ");
}

async function filterRecordsFromMysql(params) {
  const sourceHash = currentSourceHash();
  const limit = Math.min(Number(params.get("limit") || 1000), 10000);
  const fieldMatch = await mysqlSearchFieldMatch(params);
  const { sql, values } = mysqlSearchWhere(params, sourceHash, fieldMatch);
  const cursorWhere = mysqlCursorWhere(params);
  const searched = await mysqlIndexedRecordCount(sourceHash);
  const countMode = mysqlSearchCountMode(params, fieldMatch);
  const cachedTotal = countMode === "exact" ? await mysqlCachedSearchCount(params, fieldMatch, sourceHash) : null;
  const total = countMode === "exact" ? cachedTotal ?? await mysqlSearchCount(sql, values) : null;
  const [rows] = await timedMysqlExecute(
    "search-list",
    `${mysqlRecordSelect(false)}
     WHERE ${sql}${cursorWhere.sql}
     ORDER BY timestamp_dt DESC, id_hash DESC
     LIMIT ?`,
    [...values, ...cursorWhere.values, limit + 1]
  );
  const records = rows.slice(0, limit).map(mysqlRowToRecord);
  const hasMore = rows.length > limit;
  return {
    searched,
    total,
    totalIsExact: countMode === "exact",
    limit,
    hasMore,
    nextCursor: hasMore ? encodeSearchCursor(records[records.length - 1]) : "",
    rows: records
  };
}

function mysqlSearchCountMode(params, fieldMatch = null) {
  if (params.get("exactTotal") === "1") return "exact";
  if (fieldMatch) return "exact";
  const q = (params.get("q") || "").trim();
  if (q && mysqlFullTextReady) return "deferred";
  return "exact";
}

async function mysqlSearchCount(sql, values) {
  const [[row]] = await timedMysqlExecute("search-count", `SELECT COUNT(*) AS count FROM log_events WHERE ${sql}`, values);
  return Number(row.count || 0);
}

async function mysqlCachedSearchCount(params, fieldMatch, sourceHash) {
  const q = (params.get("q") || "").trim();
  const category = params.get("category") || "";
  const eventName = params.get("eventName") || "";
  const os = params.get("os") || "";
  const gateway = params.get("gateway") || "";
  const start = params.get("start") || "";
  const end = params.get("end") || "";
  if (category || os || gateway || start || end) return null;
  const searched = await mysqlIndexedRecordCount(sourceHash);
  if (!q && !eventName) return searched;
  const eventValue = eventName || (fieldMatch && fieldMatch.column === "event_name" ? fieldMatch.value : "");
  if (!eventValue) return null;
  const [rows] = await timedMysqlExecute(
    "stats-cache-event-count",
    "SELECT by_event_json FROM log_stats_cache WHERE source_hash = ? LIMIT 1",
    [sourceHash]
  );
  if (!rows.length) return null;
  const byEvent = parseMysqlJson(rows[0].by_event_json, {});
  return Number(byEvent[eventValue] || 0);
}

async function mysqlSearchFieldMatch(params) {
  const q = (params.get("q") || "").trim();
  if (!q || q.includes(" ")) return null;
  const facetsData = await cachedFacetsFromMysql();
  if (!facetsData) return null;
  const checks = [
    ["eventNames", "event_name"],
    ["categories", "category"],
    ["users", "user_name"],
    ["ips", "public_ip"],
    ["gateways", "gateway"]
  ];
  const normalized = q.toLowerCase();
  for (const [key, column] of checks) {
    const values = Array.isArray(facetsData[key]) ? facetsData[key] : [];
    const match = values.find((value) => String(value).toLowerCase() === normalized);
    if (match) return { column, value: match };
  }
  return null;
}

async function mysqlIndexedRecordCount(sourceHash) {
  const [cacheRows] = await mysqlPool.execute(
    "SELECT records FROM log_stats_cache WHERE source_hash = ? LIMIT 1",
    [sourceHash]
  );
  if (cacheRows.length) return Number(cacheRows[0].records || 0);
  const [[row]] = await mysqlPool.execute("SELECT COUNT(*) AS count FROM log_events WHERE source_hash = ?", [sourceHash]);
  return Number(row.count || 0);
}

async function facetsFromMysql() {
  const cached = await cachedFacetsFromMysql();
  if (cached) return cached;
  return buildFacetsFromMysql();
}

async function cachedFacetsFromMysql() {
  const sourceHash = currentSourceHash();
  const [rows] = await timedMysqlExecute(
    "facets-cache",
    `SELECT categories_json,
            event_names_json,
            operating_systems_json,
            gateways_json,
            users_json,
            ips_json
     FROM log_facets_cache
     WHERE source_hash = ?
     LIMIT 1`,
    [sourceHash]
  );
  if (!rows.length) return null;
  const row = rows[0];
  return {
    categories: parseMysqlJson(row.categories_json, []),
    eventNames: parseMysqlJson(row.event_names_json, []),
    operatingSystems: parseMysqlJson(row.operating_systems_json, []),
    gateways: parseMysqlJson(row.gateways_json, []),
    users: parseMysqlJson(row.users_json, []),
    ips: parseMysqlJson(row.ips_json, [])
  };
}

async function buildFacetsFromMysql() {
  const sourceHash = currentSourceHash();
  const distinct = async (column, suffix = "") => {
    const [rows] = await timedMysqlExecute(
      "facets-distinct-" + column,
      `SELECT DISTINCT ${column} AS value FROM log_events WHERE source_hash = ? AND ${column} <> '' ORDER BY ${column} LIMIT 250`,
      [sourceHash]
    );
    const values = rows.map((row) => String(row.value || ""));
    return suffix ? unique(values.map((value) => value.split(suffix)[0])) : values;
  };
  return {
    categories: await distinct("category"),
    eventNames: await distinct("event_name"),
    operatingSystems: await distinct("os", " "),
    gateways: await distinct("gateway"),
    users: (await distinct("user_name")).slice(0, 25),
    ips: (await distinct("public_ip")).slice(0, 25)
  };
}

async function updateMysqlFacetsCache(sourceHash, generatedAt) {
  const facetsData = await buildFacetsFromMysql();
  await timedMysqlExecute(
    "facets-cache-upsert",
    `INSERT INTO log_facets_cache (
       source_hash,
       categories_json,
       event_names_json,
       operating_systems_json,
       gateways_json,
       users_json,
       ips_json,
       generated_at
     )
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       categories_json = VALUES(categories_json),
       event_names_json = VALUES(event_names_json),
       operating_systems_json = VALUES(operating_systems_json),
       gateways_json = VALUES(gateways_json),
       users_json = VALUES(users_json),
       ips_json = VALUES(ips_json),
       generated_at = VALUES(generated_at)`,
    [
      sourceHash,
      JSON.stringify(facetsData.categories || []),
      JSON.stringify(facetsData.eventNames || []),
      JSON.stringify(facetsData.operatingSystems || []),
      JSON.stringify(facetsData.gateways || []),
      JSON.stringify(facetsData.users || []),
      JSON.stringify(facetsData.ips || []),
      generatedAt
    ]
  );
}

async function recordFromMysql(id) {
  const [rows] = await mysqlPool.execute(
    `${mysqlRecordSelect(true)} WHERE source_hash = ? AND id_hash = ? LIMIT 1`,
    [currentSourceHash(), hashId(id)]
  );
  return rows.length ? mysqlRowToRecord(rows[0]) : null;
}

async function statsFromMysql(timeZone = "UTC") {
  const cached = await cachedStatsFromMysql(timeZone);
  if (cached) return cached;
  return buildStatsFromMysql(timeZone);
}

async function cachedStatsFromMysql(timeZone = "UTC") {
  const sourceHash = currentSourceHash();
  const [rows] = await mysqlPool.execute(
    `SELECT records,
            objects,
            active_sessions,
            active_users,
            first_timestamp,
            last_timestamp,
            total_bytes_in,
            total_bytes_out,
            by_event_json,
            by_day_json,
            generated_at
     FROM log_stats_cache
     WHERE source_hash = ?
     LIMIT 1`,
    [sourceHash]
  );
  if (!rows.length) return null;
  const row = rows[0];
  return {
    records: Number(row.records || 0),
    objects: Number(row.objects || store.objects.length || 0),
    activeSessions: Number(row.active_sessions || 0),
    activeUsers: Number(row.active_users || 0),
    mysql: mysqlStatus,
    byEvent: parseMysqlJson(row.by_event_json, {}),
    totalBytesIn: Number(row.total_bytes_in || 0),
    totalBytesOut: Number(row.total_bytes_out || 0),
    source: store.source,
    loadedAt: row.generated_at ? new Date(row.generated_at).toISOString() : store.loadedAt,
    error: store.error,
    loading: Boolean(refreshPromise),
    firstTimestamp: row.first_timestamp || "",
    lastTimestamp: row.last_timestamp || "",
    timeZone: normalizeTimeZone(timeZone),
    byDay: parseMysqlJson(row.by_day_json, {})
  };
}

function parseMysqlJson(value, fallback) {
  try {
    return JSON.parse(value || "");
  } catch {
    return fallback;
  }
}

async function buildStatsFromMysql(timeZone = "UTC") {
  const sourceHash = currentSourceHash();
  const displayTimeZone = normalizeTimeZone(timeZone);
  const [[summary]] = await mysqlPool.execute(
    `SELECT COUNT(*) AS records,
            MIN(timestamp_text) AS firstTimestamp,
            MAX(timestamp_text) AS lastTimestamp,
            COALESCE(SUM(bytes_in), 0) AS totalBytesIn,
            COALESCE(SUM(bytes_out), 0) AS totalBytesOut
     FROM log_events
     WHERE source_hash = ?`,
    [sourceHash]
  );
  const [[objectsRow]] = await mysqlPool.execute(
    "SELECT COUNT(*) AS objects FROM log_s3_objects WHERE source_hash = ?",
    [sourceHash]
  );
  const [eventRows] = await mysqlPool.execute(
    "SELECT event_name, COUNT(*) AS count FROM log_events WHERE source_hash = ? AND event_name <> '' GROUP BY event_name",
    [sourceHash]
  );
  const [dayRows] = await mysqlPool.execute(
    "SELECT date_text, COUNT(*) AS count FROM log_events WHERE source_hash = ? AND date_text <> '' GROUP BY date_text ORDER BY date_text",
    [sourceHash]
  );
  const newest = summary.lastTimestamp ? Date.parse(summary.lastTimestamp) : Date.now();
  const activeRows = await latestActiveConnectionsFromMysql(newest);
  return {
    records: Number(summary.records || 0),
    objects: Number(objectsRow.objects || store.objects.length || 0),
    activeSessions: activeRows.length,
    activeUsers: unique(activeRows.map((session) => session.userName)).length,
    mysql: mysqlStatus,
    byEvent: Object.fromEntries(eventRows.map((row) => [row.event_name, Number(row.count || 0)])),
    totalBytesIn: Number(summary.totalBytesIn || 0),
    totalBytesOut: Number(summary.totalBytesOut || 0),
    source: store.source,
    loadedAt: store.loadedAt,
    error: store.error,
    loading: Boolean(refreshPromise),
    firstTimestamp: summary.firstTimestamp || "",
    lastTimestamp: summary.lastTimestamp || "",
    timeZone: displayTimeZone,
    byDay: Object.fromEntries(dayRows.map((row) => [row.date_text, Number(row.count || 0)]))
  };
}

async function updateMysqlMaterializedViews() {
  if (!mysqlPool || !mysqlLogIndexReady) return;
  const sourceHash = currentSourceHash();
  const statsData = await buildStatsFromMysql("UTC");
  const generatedAt = mysqlDate(new Date());
  await mysqlPool.execute(
    `INSERT INTO log_stats_cache (
       source_hash,
       records,
       objects,
       active_sessions,
       active_users,
       first_timestamp,
       last_timestamp,
       total_bytes_in,
       total_bytes_out,
       by_event_json,
       by_day_json,
       generated_at
     )
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       records = VALUES(records),
       objects = VALUES(objects),
       active_sessions = VALUES(active_sessions),
       active_users = VALUES(active_users),
       first_timestamp = VALUES(first_timestamp),
       last_timestamp = VALUES(last_timestamp),
       total_bytes_in = VALUES(total_bytes_in),
       total_bytes_out = VALUES(total_bytes_out),
       by_event_json = VALUES(by_event_json),
       by_day_json = VALUES(by_day_json),
       generated_at = VALUES(generated_at)`,
    [
      sourceHash,
      statsData.records,
      statsData.objects,
      statsData.activeSessions,
      statsData.activeUsers,
      statsData.firstTimestamp,
      statsData.lastTimestamp,
      statsData.totalBytesIn,
      statsData.totalBytesOut,
      JSON.stringify(statsData.byEvent || {}),
      JSON.stringify(statsData.byDay || {}),
      generatedAt
    ]
  );
  const newest = statsData.lastTimestamp ? Date.parse(statsData.lastTimestamp) : Date.now();
  const activeRows = await latestActiveConnectionsFromMysql(newest);
  await timedMysqlExecute("active-snapshot-clear", "DELETE FROM active_sessions_snapshot WHERE source_hash = ?", [sourceHash]);
  await insertActiveSessionSnapshotRows(sourceHash, activeRows, generatedAt);
  await updateMysqlFacetsCache(sourceHash, generatedAt);
  await updateMysqlChurnCache(sourceHash, generatedAt);
}

async function insertActiveSessionSnapshotRows(sourceHash, activeRows, generatedAt) {
  if (!activeRows.length) return;
  const placeholders = activeRows.map(() => "(?, ?, ?, ?, ?, ?)").join(", ");
  const values = activeRows.flatMap((session) => [
    sourceHash,
    session.userName,
    session.sessionId || "",
    Number.isFinite(session.timestamp) ? mysqlDate(new Date(session.timestamp)) : null,
    Number.isFinite(session.timestamp) ? new Date(session.timestamp).toISOString() : "",
    generatedAt
  ]);
  await timedMysqlExecute(
    "active-snapshot-insert",
    `INSERT INTO active_sessions_snapshot (
       source_hash,
       user_name,
       session_id,
       event_timestamp,
       timestamp_text,
       generated_at
     )
     VALUES ${placeholders}`,
    values
  );
}

async function connectionRecordsFromMysqlSince(cutoff) {
  const [rows] = await mysqlPool.execute(
    `${mysqlRecordSelect(false)}
     WHERE source_hash = ?
       AND event_name IN ('client-connected', 'client-disconnected')
       AND timestamp_dt >= ?
     ORDER BY timestamp_dt ASC, id_hash ASC`,
    [currentSourceHash(), mysqlDate(new Date(cutoff))]
  );
  return rows.map(mysqlRowToRecord);
}

async function latestActiveConnectionsFromMysql(atTime = Date.now()) {
  const staleCutoff = atTime - (ACTIVE_SESSION_MAX_AGE_HOURS * 60 * 60 * 1000);
  const records = await connectionRecordsFromMysqlSince(staleCutoff);
  const latestByUser = new Map();
  for (const record of records) {
    const userName = recordUserName(record);
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
  return [...latestByUser.values()].filter((session) => session.eventName === "client-connected" && session.timestamp >= staleCutoff);
}

async function connectedUsersSnapshotFromMysql() {
  const [[row]] = await mysqlPool.execute(
    "SELECT MAX(timestamp_text) AS newest FROM log_events WHERE source_hash = ?",
    [currentSourceHash()]
  );
  const newest = row.newest ? Date.parse(row.newest) : Date.now();
  const cutoff = newest - (24 * 60 * 60 * 1000);
  const excludedUsers = await excessiveReconnectUsersFromMysql(newest, cutoff);
  const activeRows = (await activeConnectionsSnapshotFromMysql(newest)).filter((session) => !excludedUsers.has(session.userName));
  return {
    connectedUsers: new Set(activeRows.map((session) => session.userName)).size,
    excludedUsers: excludedUsers.size,
    generatedAt: new Date(newest).toISOString()
  };
}

async function activeConnectionsSnapshotFromMysql(atTime = Date.now()) {
  const staleCutoff = atTime - (ACTIVE_SESSION_MAX_AGE_HOURS * 60 * 60 * 1000);
  const [rows] = await mysqlPool.execute(
    `SELECT user_name, session_id, event_timestamp, timestamp_text
     FROM active_sessions_snapshot
     WHERE source_hash = ?
       AND (event_timestamp IS NULL OR event_timestamp >= ?)
     ORDER BY user_name`,
    [currentSourceHash(), mysqlDate(new Date(staleCutoff))]
  );
  if (!rows.length) return latestActiveConnectionsFromMysql(atTime);
  return rows.map((row) => ({
    userName: row.user_name,
    sessionId: row.session_id || "",
    eventName: "client-connected",
    timestamp: row.event_timestamp ? Date.parse(row.event_timestamp) : Date.parse(row.timestamp_text)
  }));
}

async function excessiveReconnectUsersFromMysql(newest, cutoff) {
  const records = await connectionRecordsFromMysqlSince(cutoff);
  return excessiveReconnectUsers(newest, cutoff, records);
}

async function churnLeaderboardFromMysql(limit = 10) {
  const cached = await cachedChurnLeaderboardFromMysql(limit);
  if (cached) return cached;
  return buildChurnLeaderboardFromMysql(limit);
}

async function cachedChurnLeaderboardFromMysql(limit = 10) {
  const [rows] = await timedMysqlExecute(
    "churn-cache",
    "SELECT payload_json FROM churn_watch_cache WHERE source_hash = ? LIMIT 1",
    [currentSourceHash()]
  );
  if (!rows.length) return null;
  const payload = parseMysqlJson(rows[0].payload_json, null);
  if (!payload || !Array.isArray(payload.users)) return null;
  return {
    ...payload,
    users: payload.users.slice(0, limit)
  };
}

async function buildChurnLeaderboardFromMysql(limit = 10) {
  const [[row]] = await mysqlPool.execute(
    "SELECT MAX(timestamp_text) AS newest FROM log_events WHERE source_hash = ?",
    [currentSourceHash()]
  );
  const newest = row.newest ? Date.parse(row.newest) : Date.now();
  const cutoff = newest - (24 * 60 * 60 * 1000);
  const records = await connectionRecordsFromMysqlSince(cutoff);
  return churnLeaderboard(limit, records);
}

async function updateMysqlChurnCache(sourceHash, generatedAt) {
  const payload = await buildChurnLeaderboardFromMysql(50);
  await timedMysqlExecute(
    "churn-cache-upsert",
    `INSERT INTO churn_watch_cache (source_hash, payload_json, generated_at)
     VALUES (?, ?, ?)
     ON DUPLICATE KEY UPDATE
       payload_json = VALUES(payload_json),
       generated_at = VALUES(generated_at)`,
    [sourceHash, JSON.stringify(payload), generatedAt]
  );
}

async function userChurnSummaryFromMysql(userName) {
  if (!userName) return userChurnSummary(userName);
  const [[row]] = await mysqlPool.execute(
    "SELECT MAX(timestamp_text) AS newest FROM log_events WHERE source_hash = ?",
    [currentSourceHash()]
  );
  const newest = row.newest ? Date.parse(row.newest) : Date.now();
  const cutoff = newest - (24 * 60 * 60 * 1000);
  const [rows] = await mysqlPool.execute(
    `${mysqlRecordSelect(false)}
     WHERE source_hash = ?
       AND timestamp_dt >= ?
       AND (user_name = ? OR parent_entity_name = ? OR initiator_name = ?)
     ORDER BY timestamp_dt DESC, id_hash DESC`,
    [currentSourceHash(), mysqlDate(new Date(cutoff)), userName, userName, userName]
  );
  return userChurnSummary(userName, rows.map(mysqlRowToRecord));
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
    await updateMysqlMaterializedViews();
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
      await updateMysqlMaterializedViews();
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

function userChurnSummary(userName, records = store.records) {
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
  const newest = newestRecordTimestamp(records);
  const cutoff = newest - (windowHours * 60 * 60 * 1000);
  const userRecords = records.filter((record) => {
    if (recordUserName(record) !== userName) return false;
    const ts = Date.parse(record.timestamp);
    return Number.isFinite(ts) && ts >= cutoff;
  });

  const connected = userRecords.filter((record) => record.eventName === "client-connected").length;
  const disconnected = userRecords.filter((record) => record.eventName === "client-disconnected").length;
  const shortSessions = userRecords.filter((record) => record.eventName === "client-disconnected" && record.durationSeconds > 0 && record.durationSeconds <= 60).length;
  const totalTransfer = userRecords.reduce((sum, record) => sum + (record.bytesIn || 0) + (record.bytesOut || 0), 0);
  const connectedForSeconds = connectedSecondsByUser(newest, cutoff, records).get(userName) || 0;
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

function churnLeaderboard(limit = 10, records = store.records) {
  const windowHours = 24;
  const newest = newestRecordTimestamp(records);
  const cutoff = newest - (windowHours * 60 * 60 * 1000);
  const users = new Map();
  const connectedSeconds = connectedSecondsByUser(newest, cutoff, records);

  for (const record of records) {
    if (record.eventName !== "client-connected" && record.eventName !== "client-disconnected") continue;
    const ts = Date.parse(record.timestamp);
    if (!Number.isFinite(ts) || ts < cutoff) continue;
    const userName = recordUserName(record);
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

function excessiveReconnectUsers(newest, cutoff, records = store.records) {
  const users = new Map();
  for (const record of records) {
    if (record.eventName !== "client-connected" && record.eventName !== "client-disconnected") continue;
    const ts = Date.parse(record.timestamp);
    if (!Number.isFinite(ts) || ts < cutoff) continue;
    const userName = recordUserName(record);
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

function connectionSessions(records = store.records) {
  const sessions = new Map();
  for (const record of records) {
    if (!record.sessionId || (record.eventName !== "client-connected" && record.eventName !== "client-disconnected")) continue;
    if (!sessions.has(record.sessionId)) {
      sessions.set(record.sessionId, {
        userName: recordUserName(record),
        start: Number.POSITIVE_INFINITY,
        end: null,
        latestTimestamp: ""
      });
    }
    const session = sessions.get(record.sessionId);
    if (!session.userName) session.userName = recordUserName(record);
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

function connectedSecondsByUser(newest, cutoff, records = store.records) {
  const byUser = new Map();
  for (const session of connectionSessions(records)) {
    const end = session.end || newest;
    const overlapStart = Math.max(session.start, cutoff);
    const overlapEnd = Math.min(end, newest);
    const seconds = Math.max(0, Math.floor((overlapEnd - overlapStart) / 1000));
    byUser.set(session.userName, (byUser.get(session.userName) || 0) + seconds);
  }
  return byUser;
}

function newestRecordTimestamp(records = store.records) {
  let newest = 0;
  for (const record of records) {
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
    const userName = recordUserName(record);
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

async function connectedUsersExport(format = "csv", range = "year") {
  const normalizedRange = ["week", "month", "year", "all"].includes(range) ? range : "year";
  const rows = mysqlPool
    ? await connectedUsersExportRowsFromMysql(normalizedRange)
    : inMemoryConnectedUsersSeries(normalizedRange === "all" ? "year" : normalizedRange).points.map((point) => ({
      timestamp: point.timestamp,
      connectedUsers: point.connectedUsers,
      excludedUsers: point.excludedUsers || 0
    }));
  if (format === "json") {
    return {
      range: normalizedRange,
      retentionDays: 365,
      rows
    };
  }
  return csv([
    ["sampled_at", "connected_users", "excluded_users"],
    ...rows.map((row) => [row.timestamp, row.connectedUsers, row.excludedUsers])
  ]);
}

async function connectedUsersExportRowsFromMysql(range) {
  const daysByRange = { week: 7, month: 31, year: 365 };
  const where = range === "all" ? "" : "WHERE sampled_at >= UTC_TIMESTAMP() - INTERVAL ? DAY";
  const values = range === "all" ? [] : [daysByRange[range] || 365];
  const [rows] = await timedMysqlExecute(
    "connected-users-export",
    `SELECT sampled_at, connected_users, excluded_users
     FROM connected_user_counts
     ${where}
     ORDER BY sampled_at`,
    values
  );
  return rows.map((row) => ({
    timestamp: new Date(row.sampled_at).toISOString(),
    connectedUsers: Number(row.connected_users),
    excludedUsers: Number(row.excluded_users)
  }));
}

function csv(rows) {
  return rows.map((row) => row.map((value) => {
    const text = String(value ?? "");
    return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
  }).join(",")).join("\n") + "\n";
}

async function healthSummary() {
  const memory = process.memoryUsage();
  const statsData = mysqlLogIndexAvailable() ? await statsFromMysql() : stats();
  const mysql = mysqlPool ? await mysqlHealth() : { enabled: false, status: mysqlStatus };
  return {
    status: statsData.error ? "degraded" : "ok",
    generatedAt: new Date().toISOString(),
    process: {
      pid: process.pid,
      uptimeSeconds: Math.round(process.uptime()),
      rssBytes: memory.rss,
      heapUsedBytes: memory.heapUsed,
      heapTotalBytes: memory.heapTotal,
      node: process.version
    },
    config: {
      port: PORT,
      mysqlEnabled: MYSQL_ENABLED,
      webIngestEnabled: WEB_INGEST_ENABLED,
      autoRefreshMinutes: AUTO_REFRESH_MINUTES,
      fetchConcurrency: FETCH_CONCURRENCY,
      activeSessionMaxAgeHours: ACTIVE_SESSION_MAX_AGE_HOURS,
      logIndexRetentionDays: LOG_INDEX_RETENTION_DAYS,
      slowApiMs: SLOW_API_MS,
      slowDbMs: SLOW_DB_MS
    },
    source: {
      type: sourceConfig().mode,
      description: publicSourceSettings()
    },
    app: {
      loading: Boolean(refreshPromise),
      loadedAt: statsData.loadedAt,
      source: statsData.source,
      error: statsData.error,
      records: statsData.records,
      objects: statsData.objects,
      activeUsers: statsData.activeUsers,
      activeSessions: statsData.activeSessions
    },
    mysql,
    slowEvents: slowEvents.slice(-25).reverse()
  };
}

async function mysqlHealth() {
  const sourceHash = currentSourceHash();
  const [[versionRow]] = await timedMysqlExecute("health-version", "SELECT VERSION() AS version");
  const [tables] = await timedMysqlExecute(
    "health-tables",
    `SELECT table_name,
            table_rows,
            data_length,
            index_length
     FROM information_schema.tables
     WHERE table_schema = DATABASE()
       AND table_name IN (
         'log_events',
         'log_s3_objects',
         'connected_user_counts',
         'log_stats_cache',
         'log_facets_cache',
         'churn_watch_cache',
         'active_sessions_snapshot'
       )
     ORDER BY table_name`
  );
  const [cacheRows] = await timedMysqlExecute(
    "health-caches",
    `SELECT 'stats' AS cache_name, MAX(generated_at) AS generated_at FROM log_stats_cache WHERE source_hash = ?
     UNION ALL SELECT 'facets', MAX(generated_at) FROM log_facets_cache WHERE source_hash = ?
     UNION ALL SELECT 'churn', MAX(generated_at) FROM churn_watch_cache WHERE source_hash = ?
     UNION ALL SELECT 'active_sessions', MAX(generated_at) FROM active_sessions_snapshot WHERE source_hash = ?`,
    [sourceHash, sourceHash, sourceHash, sourceHash]
  );
  const [indexRows] = await timedMysqlExecute(
    "health-indexes",
    `SELECT table_name, index_name
     FROM information_schema.statistics
     WHERE table_schema = DATABASE()
       AND index_name IN (
         'search_text_ft',
         'last_modified_idx',
         'source_time_idx',
         'source_event_time_idx',
         'source_user_time_idx',
         'source_category_time_idx'
       )
     GROUP BY table_name, index_name
     ORDER BY table_name, index_name`
  );
  return {
    enabled: true,
    status: mysqlStatus,
    version: versionRow.version,
    tables: tables.map((row) => ({
      name: row.table_name,
      estimatedRows: Number(row.table_rows || 0),
      dataBytes: Number(row.data_length || 0),
      indexBytes: Number(row.index_length || 0)
    })),
    caches: cacheRows.map((row) => ({
      name: row.cache_name,
      generatedAt: row.generated_at ? new Date(row.generated_at).toISOString() : ""
    })),
    indexes: indexRows.map((row) => `${row.table_name}.${row.index_name}`)
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

function recordUserName(record) {
  return record.userName || record.parentEntityName || record.initiatorName;
}

function normalizeKeyForSecretCheck(key) {
  return String(key || "").replace(/[^a-z0-9]/gi, "").toLowerCase();
}

function redact(value, key = "") {
  if (SECRET_KEY_RE.test(normalizeKeyForSecretCheck(key))) return "[redacted]";
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

function text(res, body, contentType = "text/plain; charset=utf-8", status = 200, headers = {}) {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    ...headers
  });
  res.end(body);
}

function html(res) {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(INDEX_HTML);
}

function adminHtml(res) {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(ADMIN_HTML);
}

function notFound(res) {
  json(res, { error: "Not found" }, 404);
}

async function handler(req, res) {
  const start = Date.now();
  let label = `${req.method} ${req.url || ""}`;
  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    label = `${req.method} ${url.pathname}`;
    if (url.pathname === "/auth/saml/login") return samlLogin(req, res);
    if (url.pathname === "/auth/saml/callback" && req.method === "POST") return samlCallback(req, res);
    if (url.pathname === "/auth/saml/metadata") return samlMetadata(req, res);
    if (url.pathname === "/auth/logout") {
      clearSession(req, res);
      return redirect(res, "/");
    }
    if (samlSettings.requireAuth && !currentUser(req).authenticated && url.pathname !== "/" && url.pathname !== "/api/auth") return json(res, { error: "Authentication required" }, 401);
    if (url.pathname === "/") return html(res);
    if (url.pathname === "/admin") return adminHtml(res);
    if (url.pathname === "/api/auth") return json(res, { user: currentUser(req), saml: { enabled: samlConfig(req).enabled, ready: samlReady(req), requireAuth: samlConfig(req).requireAuth } });
    if (url.pathname === "/api/health") return json(res, await healthSummary());
    if (url.pathname === "/api/settings/saml" && req.method === "GET") return json(res, publicSamlSettings(req));
    if (url.pathname === "/api/settings/saml" && req.method === "POST") {
      if (!requireAdmin(req, res)) return;
      const nextSettings = cleanSamlSettings(await readJsonBody(req));
      if (nextSettings.requireAuth && (!nextSettings.enabled || !nextSettings.entryPoint || !nextSettings.idpCert || !nextSettings.issuer)) {
        return json(res, { error: "Require SSO can only be enabled after SAML login URL, entity ID, and IdP certificate are configured." }, 400);
      }
      await saveSamlSettings(nextSettings);
      return json(res, publicSamlSettings(req));
    }
    if (url.pathname === "/api/settings/source" && req.method === "GET") return json(res, publicSourceSettings());
    if (url.pathname === "/api/settings/source" && req.method === "POST") {
      if (!requireAdmin(req, res)) return;
      const nextSettings = cleanSourceSettings(await readJsonBody(req));
      if (nextSettings.mode === "http" && !nextSettings.bucketUrl) return json(res, { error: "S3 bucket URL is required for HTTP mode." }, 400);
      if (nextSettings.mode === "s3-api" && !nextSettings.bucketName) return json(res, { error: "S3 bucket name is required for S3 API mode." }, 400);
      await saveSourceSettings(nextSettings);
      return json(res, publicSourceSettings());
    }
    if (url.pathname === "/api/stats") return json(res, mysqlLogIndexAvailable() ? await statsFromMysql(url.searchParams.get("timeZone") || "UTC") : stats(url.searchParams.get("timeZone") || "UTC"));
    if (url.pathname === "/api/facets") return json(res, mysqlLogIndexAvailable() ? await facetsFromMysql() : facets());
    if (url.pathname === "/api/churn") {
      const limit = Math.min(Number(url.searchParams.get("limit") || 10), 50);
      return json(res, mysqlLogIndexAvailable() ? await churnLeaderboardFromMysql(limit) : churnLeaderboard(limit));
    }
    if (url.pathname === "/api/connected-users") return json(res, await connectedUsersSeries(url.searchParams.get("range") || "week"));
    if (url.pathname === "/api/connected-users/export") {
      const format = (url.searchParams.get("format") || "csv").toLowerCase();
      const requestedRange = url.searchParams.get("range") || "year";
      const range = ["week", "month", "year", "all"].includes(requestedRange) ? requestedRange : "year";
      if (format === "json") return json(res, await connectedUsersExport("json", range));
      return text(res, await connectedUsersExport("csv", range), "text/csv; charset=utf-8", 200, {
        "Content-Disposition": `attachment; filename="connected-user-counts-${range}.csv"`
      });
    }
    if (url.pathname === "/api/search") {
      const result = mysqlLogIndexAvailable() ? await filterRecordsFromMysql(url.searchParams) : filterRecords(url.searchParams);
      return json(res, {
        ...result,
        rows: result.rows.map(({ searchText, raw, ...record }) => record)
      });
    }
    if (url.pathname === "/api/record") {
      const id = url.searchParams.get("id");
      const record = mysqlLogIndexAvailable() ? await recordFromMysql(id) : store.records.find((item) => item.id === id);
      if (!record) return notFound(res);
      const raw = record.raw && Object.keys(record.raw).length ? record.raw : await loadRecordRawFromMysql(currentSourceHash(), id) || {};
      const userName = recordUserName(record);
      const churn = mysqlLogIndexAvailable() ? await userChurnSummaryFromMysql(userName) : userChurnSummary(userName);
      return json(res, { ...record, searchText: undefined, raw: redact(raw), churn });
    }
    if (url.pathname === "/api/reload" && req.method === "POST") {
      if (!WEB_INGEST_ENABLED && mysqlLogIndexAvailable()) {
        store = { ...store, error: null };
        return json(res, await statsFromMysql());
      }
      refresh().catch((error) => {
        store = { ...store, error: error.message };
        console.error(error);
      });
      return json(res, mysqlLogIndexAvailable() ? await statsFromMysql() : stats());
    }
    return notFound(res);
  } catch (error) {
    json(res, { error: error.message }, 500);
  } finally {
    logSlow("api", label, Date.now() - start);
  }
}

const ADMIN_HTML = fsSync.readFileSync(path.join(__dirname, "public", "admin.html"), "utf8");

const INDEX_HTML = fsSync.readFileSync(path.join(__dirname, "public", "index.html"), "utf8");

if (process.argv.includes("--ingest")) {
  runIngestOnce().catch((error) => {
    console.error(error);
    process.exit(1);
  });
} else if (process.argv.includes("--worker")) {
  runIngestWorker().catch((error) => {
    console.error(error);
    process.exit(1);
  });
} else {
  http.createServer(handler).listen(PORT, () => {
    console.log(`OpenVPN Log Search listening on http://localhost:${PORT}`);
    if (!adminConfigured()) {
      console.warn("SECURITY WARNING: ADMIN_SETUP_TOKEN/ADMIN_EMAILS are not set. Settings changes (/api/settings/saml, /api/settings/source) are disabled until one is configured.");
    }
    setInterval(sweepExpiredSessions, 15 * 60 * 1000);
    initializeApp().then(() => {
      if (WEB_INGEST_ENABLED) {
        refresh().catch((error) => {
          store = { ...store, error: error.message };
          console.error(error);
        });
        if (AUTO_REFRESH_MINUTES > 0) {
          setInterval(() => {
            refresh().catch((error) => {
              store = { ...store, error: error.message };
              console.error(error);
            });
          }, AUTO_REFRESH_MINUTES * 60 * 1000);
        }
      }
    }).catch(console.error);
  });
}

async function initializeApp() {
  await Promise.all([loadSamlSettings(), loadSourceSettings()]);
  await initMysql().catch((error) => {
    mysqlStatus = `unavailable: ${error.message}`;
    console.error(error);
  });
}

async function runIngestOnce() {
  await initializeApp();
  await refresh();
  console.log(JSON.stringify(mysqlLogIndexAvailable() ? await statsFromMysql() : stats(), null, 2));
}

async function runIngestWorker() {
  await initializeApp();
  console.log("OpenVPN Log Search ingest worker started.");
  for (;;) {
    try {
      await refresh();
      console.log(JSON.stringify({
        timestamp: new Date().toISOString(),
        stats: mysqlLogIndexAvailable() ? await statsFromMysql() : stats()
      }));
    } catch (error) {
      store = { ...store, error: error.message };
      console.error(error);
    }
    const delayMs = Math.max(1, AUTO_REFRESH_MINUTES || 30) * 60 * 1000;
    await yieldToEventLoop(delayMs);
  }
}
