import { api } from "../api.js";
import { getTimeZone } from "../state.js";
import { esc, shortTime, todayKey } from "../util.js";
import { navigate } from "../router.js";

function statTile(label, value) {
  return '<div class="stat"><strong>' + esc(value) + '</strong><span>' + esc(label) + '</span></div>';
}

function renderConnectedChart(container, metaEl, data, timeZone) {
  const points = data.points || [];
  metaEl.textContent = points.length ? "excluding " + (data.excludedUsers ?? 0) + " reconnect-heavy users" : "No connection data loaded";
  if (!points.length) {
    container.innerHTML = '<div class="muted">Loading connection trend...</div>';
    return;
  }
  const width = Math.max(340, Math.round(container.clientWidth || 540));
  const height = 92;
  const pad = { top: 8, right: 10, bottom: 18, left: 26 };
  const max = Math.max(1, ...points.map((point) => point.connectedUsers));
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const x = (index) => pad.left + (points.length === 1 ? 0 : (index / (points.length - 1)) * plotW);
  const y = (value) => pad.top + plotH - (value / max) * plotH;
  const line = points.map((point, index) => x(index).toFixed(1) + "," + y(point.connectedUsers).toFixed(1)).join(" ");
  const area = pad.left + "," + (pad.top + plotH) + " " + line + " " + (pad.left + plotW) + "," + (pad.top + plotH);
  const last = points[points.length - 1];
  const grid = [0, .5, 1].map((part) => {
    const gy = pad.top + plotH - part * plotH;
    const label = Math.round(max * part);
    return '<line class="chart-grid" x1="' + pad.left + '" y1="' + gy + '" x2="' + (pad.left + plotW) + '" y2="' + gy + '"></line>' +
      '<text class="chart-label" x="4" y="' + (gy + 4) + '">' + esc(label) + '</text>';
  }).join("");
  container.innerHTML = '<svg class="chart" viewBox="0 0 ' + width + ' ' + height + '" role="img" aria-label="Connected users over time">' +
    grid +
    '<polygon class="chart-area" points="' + area + '"></polygon>' +
    '<polyline class="chart-line" points="' + line + '"></polyline>' +
    '<circle class="chart-dot" cx="' + x(points.length - 1).toFixed(1) + '" cy="' + y(last.connectedUsers).toFixed(1) + '" r="3"></circle>' +
    '<text class="chart-label" x="' + pad.left + '" y="' + (height - 6) + '">' + esc(shortTime(points[0].timestamp, timeZone)) + '</text>' +
    '<text class="chart-label" text-anchor="end" x="' + (pad.left + plotW) + '" y="' + (height - 6) + '">' + esc(shortTime(last.timestamp, timeZone)) + '</text>' +
    '<text class="chart-label" text-anchor="end" x="' + (pad.left + plotW - 8) + '" y="' + Math.max(16, y(last.connectedUsers) - 8) + '">' + esc(last.connectedUsers) + ' users</text>' +
  '</svg>';
}

function renderChurnUsers(users, excessiveCount) {
  if (!users.length) return '<div class="muted">No reconnect activity recorded.</div>';
  const prioritized = excessiveCount ? users.filter((user) => user.severity === "high" || user.severity === "elevated") : users;
  const rows = prioritized.slice(0, 6);
  if (!rows.length) return '<div class="muted">No excessive reconnect pattern detected.</div>';
  const more = prioritized.length > rows.length ? '<div class="watch-more">+' + esc(prioritized.length - rows.length) + ' more</div>' : "";
  return rows.map((user) => '<div class="watch-user ' + esc(user.severity) + '">' +
    '<button type="button" class="watch-user-link" data-user="' + esc(user.userName) + '">' + esc(user.userName) + '</button>' +
    '<span>' + esc(user.total) + ' events</span>' +
  '</div>').join("") + more;
}

export async function mount(root) {
  const timeZone = getTimeZone();
  root.innerHTML =
    '<div class="view view-dashboard">' +
      '<header class="view-header"><h1>Dashboard</h1></header>' +
      '<section class="dashboard-stats" id="dashStats"></section>' +
      '<section class="dashboard-grid">' +
        '<div class="chart-panel">' +
          '<div class="chart-head">' +
            '<h2>Connected users over time</h2>' +
            '<div class="chart-controls">' +
              '<select id="connectedRange" aria-label="Time range">' +
                '<option value="week">Week</option><option value="month">Month</option><option value="year">Year</option>' +
              '</select>' +
              '<span id="connectedChartMeta">Loading...</span>' +
            '</div>' +
          '</div>' +
          '<div id="connectedChart"></div>' +
        '</div>' +
        '<div class="watch" id="churnWatch">' +
          '<div class="watch-title"><h3>Reconnect watch</h3><span>last 24h</span></div>' +
          '<div class="watch-list"><div class="muted">Loading...</div></div>' +
        '</div>' +
      '</section>' +
    '</div>';

  const statsEl = root.querySelector("#dashStats");
  const chartEl = root.querySelector("#connectedChart");
  const chartMetaEl = root.querySelector("#connectedChartMeta");
  const rangeEl = root.querySelector("#connectedRange");
  const watchEl = root.querySelector("#churnWatch");

  async function loadStats() {
    const data = await api.getStats(timeZone);
    const today = todayKey(timeZone);
    statsEl.innerHTML = [
      statTile("Active users / sessions", data.activeUsers + " / " + data.activeSessions),
      statTile("Events today", (data.byDay && data.byDay[today]) || 0),
      statTile("Events indexed", data.records),
      statTile("Data source", data.source || "-")
    ].join("");
  }

  async function loadChart(range) {
    const data = await api.getConnectedUsers(range);
    renderConnectedChart(chartEl, chartMetaEl, data, timeZone);
  }

  async function loadChurn() {
    const data = await api.getChurn(8);
    watchEl.innerHTML = '<div class="watch-title"><h3>Reconnect watch</h3><span>last ' + esc(data.windowHours) + 'h</span></div>' +
      '<div class="watch-list">' + renderChurnUsers(data.users || [], data.excessiveCount) + '</div>';
  }

  function onWatchClick(event) {
    const link = event.target.closest(".watch-user-link");
    if (!link) return;
    const params = new URLSearchParams();
    params.set("q", link.dataset.user || "");
    navigate("investigate", params);
  }

  function onRangeChange() {
    loadChart(rangeEl.value).catch(console.error);
  }

  watchEl.addEventListener("click", onWatchClick);
  rangeEl.addEventListener("change", onRangeChange);

  await Promise.all([loadStats().catch(console.error), loadChart("week").catch(console.error), loadChurn().catch(console.error)]);

  return () => {
    watchEl.removeEventListener("click", onWatchClick);
    rangeEl.removeEventListener("change", onRangeChange);
  };
}
