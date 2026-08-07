async function getJson(url, options) {
  const res = await fetch(url, options);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function postJson(url, body) {
  return getJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
}

export const api = {
  getAuth: () => getJson("/api/auth"),
  getStats: (timeZone) => getJson("/api/stats?timeZone=" + encodeURIComponent(timeZone)),
  getFacets: () => getJson("/api/facets"),
  getChurn: (limit = 8) => getJson("/api/churn?limit=" + limit),
  getConnectedUsers: (range = "week") => getJson("/api/connected-users?range=" + encodeURIComponent(range)),
  query: (params) => getJson("/api/query?" + params.toString()),
  getRecord: (id) => getJson("/api/record?id=" + encodeURIComponent(id)),
  reload: () => getJson("/api/reload", { method: "POST" }),
  getSamlSettings: () => getJson("/api/settings/saml"),
  saveSamlSettings: (body) => postJson("/api/settings/saml", body),
  getSourceSettings: () => getJson("/api/settings/source"),
  saveSourceSettings: (body) => postJson("/api/settings/source", body)
};
