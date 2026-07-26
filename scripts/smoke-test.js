#!/usr/bin/env node

const baseUrl = (process.env.SMOKE_BASE_URL || process.env.BASE_URL || "http://127.0.0.1:3017").replace(/\/+$/, "");

async function getJson(path, options) {
  const started = Date.now();
  const response = await fetch(`${baseUrl}${path}`, options);
  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch (error) {
    throw new Error(`${path} returned non-JSON response: ${text.slice(0, 160)}`);
  }
  if (!response.ok) {
    throw new Error(`${path} failed with ${response.status}: ${data.error || response.statusText}`);
  }
  return { data, elapsedMs: Date.now() - started };
}

async function getText(path, options) {
  const started = Date.now();
  const response = await fetch(`${baseUrl}${path}`, options);
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${path} failed with ${response.status}: ${text.slice(0, 160)}`);
  }
  return { text, elapsedMs: Date.now() - started, contentType: response.headers.get("content-type") || "" };
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function main() {
  const checks = [];
  const stats = await getJson("/api/stats");
  assert(Number.isFinite(Number(stats.data.records)), "stats.records is missing");
  assert(stats.data.error === null || stats.data.error === "", `stats reported error: ${stats.data.error}`);
  checks.push(["stats", stats.elapsedMs]);

  const health = await getJson("/api/health");
  assert(health.data.status, "health.status is missing");
  assert(health.data.app && Number.isFinite(Number(health.data.app.records)), "health.app.records is missing");
  checks.push(["health", health.elapsedMs]);

  const facets = await getJson("/api/facets");
  assert(Array.isArray(facets.data.eventNames), "facets.eventNames is missing");
  checks.push(["facets", facets.elapsedMs]);

  const churn = await getJson("/api/churn?limit=4");
  assert(Array.isArray(churn.data.users), "churn.users is missing");
  checks.push(["churn", churn.elapsedMs]);

  const exportCsv = await getText("/api/connected-users/export?range=year");
  assert(exportCsv.contentType.includes("text/csv"), "connected-users export is not CSV");
  assert(exportCsv.text.startsWith("sampled_at,connected_users,excluded_users"), "connected-users CSV header is missing");
  checks.push(["connected-export", exportCsv.elapsedMs]);

  const admin = await getText("/admin");
  assert(admin.text.includes("OpenVPN Log Search Admin"), "admin page title is missing");
  checks.push(["admin", admin.elapsedMs]);

  const search = await getJson("/api/search?eventName=client-connected&limit=2");
  assert(Array.isArray(search.data.rows), "search.rows is missing");
  assert(search.data.rows.length > 0, "search returned no rows");
  assert(search.data.hasMore === true || search.data.hasMore === false, "search.hasMore is missing");
  assert(!("raw" in search.data.rows[0]), "search row unexpectedly includes raw");
  assert(!("searchText" in search.data.rows[0]), "search row unexpectedly includes searchText");
  checks.push(["search", search.elapsedMs]);

  if (search.data.nextCursor) {
    const cursor = encodeURIComponent(search.data.nextCursor);
    const next = await getJson(`/api/search?eventName=client-connected&limit=2&cursor=${cursor}`);
    assert(Array.isArray(next.data.rows), "cursor search.rows is missing");
    checks.push(["search-cursor", next.elapsedMs]);
  }

  const id = encodeURIComponent(search.data.rows[0].id);
  const record = await getJson(`/api/record?id=${id}`);
  assert(record.data.id, "record.id is missing");
  assert(record.data.raw && typeof record.data.raw === "object", "record.raw is missing");
  checks.push(["record", record.elapsedMs]);

  for (const [name, elapsedMs] of checks) {
    console.log(`${name}: ${elapsedMs}ms`);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
