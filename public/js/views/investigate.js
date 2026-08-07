import { api } from "../api.js";
import {
  getTimeZone, loadColumnWidths, saveColumnWidths, defaultColumnWidths, minColumnWidths,
  loadSavedViews, saveSavedViews
} from "../state.js";
import { esc, formatDuration, formatBytes, displayTime, debounce } from "../util.js";

const MULTI_FIELDS = [
  { key: "category", label: "Category" },
  { key: "eventName", label: "Event" },
  { key: "os", label: "OS" },
  { key: "gateway", label: "Gateway" },
  { key: "userName", label: "User" },
  { key: "publicIp", label: "Public IP" }
];

const COLUMNS = [
  { key: "time", label: "Time", sort: "timestamp" },
  { key: "user", label: "User", sort: "userName" },
  { key: "event", label: "Event", sort: "eventName" },
  { key: "device", label: "Device", sort: "deviceName" },
  { key: "ip", label: "IP / Tunnel", sort: "publicIp" },
  { key: "gateway", label: "Gateway", sort: "gateway" },
  { key: "duration", label: "Duration", sort: "durationSeconds" },
  { key: "transfer", label: "Transfer", sort: null }
];

const DISPLAY_FIELDS = [
  "timestamp", "userName", "initiatorName", "eventName", "operation", "deviceName", "entityName",
  "os", "publicIp", "tunnelIp", "gateway", "gatewayRegion", "protocol", "durationSeconds", "bytesIn", "bytesOut",
  "sourceKey", "lineNumber"
];

function kv(key, value) {
  return "<div>" + esc(key) + "</div><div>" + esc(value || "-") + "</div>";
}

function churnPanel(churn, timeZone) {
  if (!churn || !churn.userName) return '<div class="muted">No user identity on this event.</div>';
  const recent = (churn.latest || []).map((item) => "<div>" +
    esc(displayTime(item.timestamp, timeZone)) + " | " + esc(item.eventName) + " | " + esc(item.deviceName || "-") + " | " + esc(item.publicIp || "-") +
    (item.durationSeconds ? " | " + esc(formatDuration(item.durationSeconds)) : "") +
  "</div>").join("");
  return '<div class="churn-summary ' + esc(churn.severity) + '">' +
    "<div>" + esc(churn.message) + "</div>" +
    '<div class="mini-grid">' +
      '<div class="mini-stat"><strong>' + esc(churn.connected) + "</strong><span>connects</span></div>" +
      '<div class="mini-stat"><strong>' + esc(churn.disconnected) + "</strong><span>disconnects</span></div>" +
      '<div class="mini-stat"><strong>' + esc(churn.shortSessions) + "</strong><span>short sessions</span></div>" +
      '<div class="mini-stat"><strong>' + esc(formatDuration(churn.connectedForSeconds)) + "</strong><span>connected for</span></div>" +
    "</div>" +
    (recent || '<div class="muted">No recent connection events.</div>') +
  "</div>";
}

function createMultiField(root, field) {
  const wrap = document.createElement("div");
  wrap.className = "filter-field";
  wrap.innerHTML =
    '<label for="mv-' + field.key + '">' + esc(field.label) + "</label>" +
    '<input type="text" id="mv-' + field.key + '" list="dl-' + field.key + '" placeholder="Type and press enter" autocomplete="off">' +
    '<datalist id="dl-' + field.key + '"></datalist>' +
    '<div class="chip-row" data-role="chips"></div>';
  root.appendChild(wrap);
  const input = wrap.querySelector("input");
  const datalist = wrap.querySelector("datalist");
  const chipRow = wrap.querySelector('[data-role="chips"]');
  const values = new Set();
  let onChange = () => {};

  function renderChips() {
    chipRow.innerHTML = [...values].map((value) =>
      '<span class="chip">' + esc(value) + '<button type="button" data-value="' + esc(value) + '" aria-label="Remove ' + esc(value) + '">&times;</button></span>'
    ).join("");
    chipRow.querySelectorAll("button").forEach((button) => {
      button.addEventListener("click", () => {
        values.delete(button.dataset.value);
        renderChips();
        onChange();
      });
    });
  }

  function addFromInput() {
    const value = input.value.trim();
    if (!value) return;
    values.add(value);
    input.value = "";
    renderChips();
    onChange();
  }

  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === ",") {
      event.preventDefault();
      addFromInput();
    }
  });
  input.addEventListener("blur", addFromInput);

  return {
    key: field.key,
    get values() { return values; },
    setOptions(options) {
      datalist.innerHTML = options.map((option) => '<option value="' + esc(option) + '">').join("");
    },
    onChange(handler) { onChange = handler; },
    clear() { values.clear(); renderChips(); },
    setValues(list) { values.clear(); (list || []).filter(Boolean).forEach((value) => values.add(value)); renderChips(); }
  };
}

export async function mount(root, routeParams) {
  const timeZone = getTimeZone();
  const state = {
    q: routeParams.get("q") || "",
    start: "",
    end: "",
    durationMin: "",
    durationMax: "",
    sort: "timestamp",
    order: "desc",
    cursor: "",
    selectedId: "",
    activeTab: "normalized",
    detailRequestId: 0
  };

  root.innerHTML =
    '<div class="view view-investigate">' +
      '<header class="view-header">' +
        "<h1>Investigate</h1>" +
        '<div class="actions">' +
          '<button type="button" class="secondary" id="toggleFilters">Filters</button>' +
          '<button type="button" class="secondary" id="clearFilters">Clear</button>' +
          '<button type="button" class="secondary" id="reloadButton">Reload</button>' +
        "</div>" +
      "</header>" +
      '<div class="investigate-layout" id="investigateLayout">' +
        '<div class="filter-backdrop" id="filterBackdrop"></div>' +
        '<aside class="filter-sidebar" id="filterSidebar">' +
          '<div class="filter-field"><label for="qInput">Search</label><input type="text" id="qInput" placeholder="user, IP, operation, device, trace id" autocomplete="off"></div>' +
          '<div id="multiFieldsRoot"></div>' +
          '<div class="filter-field"><label>Date range</label><div class="range-row"><input type="text" id="fStart" placeholder="Start (2026-05-01)"><input type="text" id="fEnd" placeholder="End"></div></div>' +
          '<div class="filter-field"><label>Duration (seconds)</label><div class="range-row"><input type="number" id="fDurationMin" placeholder="Min"><input type="number" id="fDurationMax" placeholder="Max"></div></div>' +
          '<div class="filter-field"><h3>Saved views</h3><div class="saved-view-row"><input type="text" id="savedViewName" placeholder="View name"><button type="button" class="secondary" id="saveViewButton">Save</button></div><div class="saved-views-list" id="savedViewsList"></div></div>' +
        "</aside>" +
        '<div class="investigate-main">' +
          '<div class="status-line" id="statusLine"></div>' +
          '<div class="table-scroll"><table class="events" id="eventsTable"></table><div class="table-footer" id="tableFooter" hidden><button type="button" class="secondary" id="loadMoreButton">Load more</button></div></div>' +
        "</div>" +
      "</div>" +
    "</div>";

  const qInput = root.querySelector("#qInput");
  const startInput = root.querySelector("#fStart");
  const endInput = root.querySelector("#fEnd");
  const durationMinInput = root.querySelector("#fDurationMin");
  const durationMaxInput = root.querySelector("#fDurationMax");
  const statusLine = root.querySelector("#statusLine");
  const eventsTable = root.querySelector("#eventsTable");
  const tableFooter = root.querySelector("#tableFooter");
  const loadMoreButton = root.querySelector("#loadMoreButton");
  const layout = root.querySelector("#investigateLayout");
  const filterSidebar = root.querySelector("#filterSidebar");
  const filterBackdrop = root.querySelector("#filterBackdrop");
  const savedViewsList = root.querySelector("#savedViewsList");
  const savedViewNameInput = root.querySelector("#savedViewName");

  const multiFieldsRoot = root.querySelector("#multiFieldsRoot");
  const multiFields = MULTI_FIELDS.map((field) => createMultiField(multiFieldsRoot, field));
  const multiFieldByKey = Object.fromEntries(multiFields.map((field) => [field.key, field]));

  let detailPanel = null;

  function buildParams(cursor) {
    const params = new URLSearchParams();
    if (state.q) params.set("q", state.q);
    for (const field of multiFields) {
      if (field.values.size) params.set(field.key, [...field.values].join(","));
    }
    if (state.start) params.set("start", state.start);
    if (state.end) params.set("end", state.end);
    if (state.durationMin) params.set("durationSecondsMin", state.durationMin);
    if (state.durationMax) params.set("durationSecondsMax", state.durationMax);
    params.set("sort", state.sort);
    params.set("order", state.order);
    params.set("fields", DISPLAY_FIELDS.join(","));
    params.set("limit", "500");
    if (cursor) params.set("cursor", cursor);
    return params;
  }

  function tableHeadHtml() {
    return "<colgroup>" + COLUMNS.map((col) => '<col data-col="' + col.key + '">').join("") + "</colgroup>" +
      "<thead><tr>" + COLUMNS.map((col) =>
        '<th data-col="' + col.key + '"' + (col.sort ? ' class="sortable"' : "") + ">" +
          '<div class="th-inner">' + esc(col.label) +
            (col.sort ? '<span class="sort-arrow" data-indicator="' + col.key + '"></span>' : "") +
            '<span class="col-resizer" data-resize="' + col.key + '"></span>' +
          "</div>" +
        "</th>"
      ).join("") + "</tr></thead><tbody id=\"rowsBody\"></tbody>";
  }
  eventsTable.innerHTML = tableHeadHtml();
  const rowsBody = eventsTable.querySelector("#rowsBody");

  function updateSortIndicators() {
    eventsTable.querySelectorAll("[data-indicator]").forEach((el) => {
      const col = COLUMNS.find((c) => c.key === el.dataset.indicator);
      el.textContent = col && col.sort === state.sort ? (state.order === "asc" ? "↑" : "↓") : "";
    });
  }

  function rowHtml(record) {
    const userName = record.userName || record.initiatorName || "";
    const eventLabel = record.eventName || record.operation || "event";
    const deviceName = record.deviceName || record.entityName || "";
    const transfer = formatBytes((record.bytesIn || 0) + (record.bytesOut || 0));
    return '<tr data-id="' + esc(record.id) + '"' + (record.id === state.selectedId ? ' class="selected"' : "") + '>' +
      "<td>" + esc(displayTime(record.timestamp, timeZone)) + "</td>" +
      '<td class="wrap">' + esc(userName) + "</td>" +
      '<td><span class="chip">' + esc(eventLabel) + "</span></td>" +
      '<td class="wrap">' + esc(deviceName) + '<br><span class="muted">' + esc(record.os || "") + "</span></td>" +
      '<td class="wrap">' + esc(record.publicIp || "") + '<br><span class="muted">' + esc(record.tunnelIp || "") + "</span></td>" +
      '<td class="wrap">' + esc(record.gateway || record.gatewayRegion || "") + '<br><span class="muted">' + esc(record.protocol || "") + "</span></td>" +
      "<td>" + esc(formatDuration(record.durationSeconds)) + "</td>" +
      "<td>" + esc(transfer) + "</td>" +
    "</tr>";
  }

  let lastResult = { searched: 0, total: 0, shown: 0 };

  async function search(options = {}) {
    const append = Boolean(options.append);
    updateSortIndicators();
    try {
      const params = buildParams(append ? state.cursor : "");
      const data = await api.query(params);
      state.cursor = data.nextCursor || "";
      lastResult = { searched: data.searched, total: data.total, shown: append ? lastResult.shown + data.rows.length : data.rows.length };
      const html = data.rows.map(rowHtml).join("");
      rowsBody.innerHTML = append ? rowsBody.innerHTML + html : html;
      tableFooter.hidden = !data.hasMore;
      loadMoreButton.disabled = !data.hasMore;
      statusLine.className = "status-line";
      statusLine.textContent = "searched " + lastResult.searched + " loaded events; " + lastResult.total + " matched; showing " + lastResult.shown + " of " + lastResult.total;
    } catch (error) {
      statusLine.className = "status-line error";
      statusLine.textContent = error.message;
    }
  }

  const debouncedSearch = debounce(() => search().catch(console.error), 250);

  function onFilterChanged() {
    state.cursor = "";
    debouncedSearch();
  }

  multiFields.forEach((field) => field.onChange(onFilterChanged));

  qInput.value = state.q;
  qInput.addEventListener("input", () => {
    state.q = qInput.value.trim();
    onFilterChanged();
  });
  [startInput, endInput, durationMinInput, durationMaxInput].forEach((input) => {
    input.addEventListener("change", () => {
      state.start = startInput.value.trim();
      state.end = endInput.value.trim();
      state.durationMin = durationMinInput.value.trim();
      state.durationMax = durationMaxInput.value.trim();
      onFilterChanged();
    });
  });

  root.querySelector("#clearFilters").addEventListener("click", () => {
    state.q = ""; state.start = ""; state.end = ""; state.durationMin = ""; state.durationMax = "";
    qInput.value = ""; startInput.value = ""; endInput.value = ""; durationMinInput.value = ""; durationMaxInput.value = "";
    multiFields.forEach((field) => field.clear());
    onFilterChanged();
  });

  root.querySelector("#reloadButton").addEventListener("click", async () => {
    statusLine.textContent = "Reloading...";
    try {
      await api.reload();
      await search();
    } catch (error) {
      statusLine.className = "status-line error";
      statusLine.textContent = error.message;
    }
  });

  loadMoreButton.addEventListener("click", () => search({ append: true }).catch(console.error));

  root.querySelector("#toggleFilters").addEventListener("click", () => {
    filterSidebar.classList.toggle("open");
    filterBackdrop.classList.toggle("open");
  });
  filterBackdrop.addEventListener("click", () => {
    filterSidebar.classList.remove("open");
    filterBackdrop.classList.remove("open");
  });

  eventsTable.addEventListener("click", (event) => {
    const th = event.target.closest("th.sortable");
    if (th) {
      const col = COLUMNS.find((c) => c.key === th.dataset.col);
      if (!col || !col.sort) return;
      if (state.sort === col.sort) state.order = state.order === "asc" ? "desc" : "asc";
      else { state.sort = col.sort; state.order = "desc"; }
      state.cursor = "";
      search().catch(console.error);
      return;
    }
    const tr = event.target.closest("tr[data-id]");
    if (!tr) return;
    if (tr.dataset.id === state.selectedId) {
      closeDetail();
    } else {
      selectRecord(tr.dataset.id).catch(console.error);
    }
  });

  function highlightSelectedRow() {
    rowsBody.querySelectorAll("tr").forEach((tr) => tr.classList.toggle("selected", tr.dataset.id === state.selectedId));
  }

  function ensureDetailPanel() {
    if (detailPanel) return detailPanel;
    detailPanel = document.createElement("aside");
    detailPanel.className = "detail-inspector";
    detailPanel.innerHTML =
      '<div class="detail-head"><h2>Event detail</h2><button type="button" class="icon-button" id="closeDetail" aria-label="Close">&times;</button></div>' +
      '<div class="detail-tabs">' +
        '<button type="button" class="detail-tab active" data-tab="normalized">Normalized</button>' +
        '<button type="button" class="detail-tab" data-tab="raw">Raw JSON</button>' +
        '<button type="button" class="detail-tab" data-tab="churn">Reconnect activity</button>' +
      "</div>" +
      '<div class="detail-body">' +
        '<div class="detail-pane" data-pane="normalized"></div>' +
        '<div class="detail-pane" data-pane="raw" hidden></div>' +
        '<div class="detail-pane" data-pane="churn" hidden></div>' +
      "</div>";
    layout.appendChild(detailPanel);
    detailPanel.querySelector("#closeDetail").addEventListener("click", closeDetail);
    detailPanel.querySelectorAll(".detail-tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        state.activeTab = tab.dataset.tab;
        detailPanel.querySelectorAll(".detail-tab").forEach((t) => t.classList.toggle("active", t === tab));
        detailPanel.querySelectorAll(".detail-pane").forEach((pane) => { pane.hidden = pane.dataset.pane !== state.activeTab; });
      });
    });
    return detailPanel;
  }

  async function selectRecord(id) {
    state.selectedId = id;
    state.detailRequestId += 1;
    const requestId = state.detailRequestId;
    highlightSelectedRow();
    const panel = ensureDetailPanel();
    layout.classList.add("detail-open");
    panel.querySelector('[data-pane="normalized"]').innerHTML = '<div class="muted">Loading...</div>';
    panel.querySelector('[data-pane="raw"]').innerHTML = '<div class="muted">Loading...</div>';
    panel.querySelector('[data-pane="churn"]').innerHTML = '<div class="muted">Loading...</div>';
    let record;
    try {
      record = await api.getRecord(id);
    } catch (error) {
      if (requestId !== state.detailRequestId) return;
      const message = '<div class="status-line error">' + esc(error.message) + "</div>";
      panel.querySelector('[data-pane="normalized"]').innerHTML = message;
      panel.querySelector('[data-pane="raw"]').innerHTML = message;
      panel.querySelector('[data-pane="churn"]').innerHTML = message;
      return;
    }
    if (requestId !== state.detailRequestId) return;
    const normalized =
      kv("Timestamp", displayTime(record.timestamp, timeZone)) +
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
      kv("Source", record.sourceKey + ":" + record.lineNumber);
    panel.querySelector('[data-pane="normalized"]').innerHTML = '<div class="kv">' + normalized + "</div>";
    panel.querySelector('[data-pane="raw"]').innerHTML = '<pre class="raw-json">' + esc(JSON.stringify(record.raw, null, 2)) + "</pre>";
    panel.querySelector('[data-pane="churn"]').innerHTML = churnPanel(record.churn, timeZone);
  }

  function closeDetail() {
    state.selectedId = "";
    layout.classList.remove("detail-open");
    if (detailPanel) { detailPanel.remove(); detailPanel = null; }
    highlightSelectedRow();
  }

  function applyColumnWidths(widths = loadColumnWidths()) {
    eventsTable.querySelectorAll("col[data-col]").forEach((col) => {
      const key = col.dataset.col;
      const min = minColumnWidths[key] || 80;
      const width = Math.max(min, Number(widths[key] || defaultColumnWidths[key] || min));
      col.style.width = width + "px";
    });
  }

  function setupResizableColumns() {
    applyColumnWidths();
    eventsTable.querySelectorAll("[data-resize]").forEach((handle) => {
      handle.addEventListener("pointerdown", (event) => {
        event.preventDefault();
        event.stopPropagation();
        const key = handle.dataset.resize;
        const widths = loadColumnWidths();
        const startX = event.clientX;
        const col = eventsTable.querySelector('col[data-col="' + key + '"]');
        const startWidth = Number(widths[key] || col.getBoundingClientRect().width || defaultColumnWidths[key]);
        const min = minColumnWidths[key] || 80;
        document.body.classList.add("resizing-columns");
        handle.setPointerCapture(event.pointerId);
        const move = (moveEvent) => {
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

  function renderSavedViews() {
    const views = loadSavedViews();
    savedViewsList.innerHTML = views.map((view, index) =>
      '<div class="saved-view-row"><button type="button" class="ghost" data-apply="' + index + '">' + esc(view.name) +
      '</button><button type="button" class="remove" data-remove="' + index + '" aria-label="Remove ' + esc(view.name) + '">&times;</button></div>'
    ).join("") || '<div class="muted">No saved views yet.</div>';
  }

  savedViewsList.addEventListener("click", (event) => {
    const applyButton = event.target.closest("[data-apply]");
    const removeButton = event.target.closest("[data-remove]");
    const views = loadSavedViews();
    if (applyButton) {
      const view = views[Number(applyButton.dataset.apply)];
      if (!view) return;
      state.q = view.q || ""; qInput.value = state.q;
      state.start = view.start || ""; startInput.value = state.start;
      state.end = view.end || ""; endInput.value = state.end;
      state.durationMin = view.durationMin || ""; durationMinInput.value = state.durationMin;
      state.durationMax = view.durationMax || ""; durationMaxInput.value = state.durationMax;
      multiFields.forEach((field) => field.setValues((view.multi || {})[field.key] || []));
      onFilterChanged();
    } else if (removeButton) {
      views.splice(Number(removeButton.dataset.remove), 1);
      saveSavedViews(views);
      renderSavedViews();
    }
  });

  root.querySelector("#saveViewButton").addEventListener("click", () => {
    const name = savedViewNameInput.value.trim();
    if (!name) return;
    const views = loadSavedViews();
    views.push({
      name,
      q: state.q,
      start: startInput.value.trim(),
      end: endInput.value.trim(),
      durationMin: durationMinInput.value.trim(),
      durationMax: durationMaxInput.value.trim(),
      multi: Object.fromEntries(multiFields.map((field) => [field.key, [...field.values]]))
    });
    saveSavedViews(views);
    savedViewNameInput.value = "";
    renderSavedViews();
  });

  async function loadFacets() {
    const data = await api.getFacets();
    multiFieldByKey.category.setOptions(data.categories || []);
    multiFieldByKey.eventName.setOptions(data.eventNames || []);
    multiFieldByKey.os.setOptions(data.operatingSystems || []);
    multiFieldByKey.gateway.setOptions(data.gateways || []);
    multiFieldByKey.userName.setOptions(data.users || []);
    multiFieldByKey.publicIp.setOptions(data.ips || []);
  }

  setupResizableColumns();
  renderSavedViews();
  await Promise.all([loadFacets().catch(console.error), search()]);

  return () => {
    if (detailPanel) detailPanel.remove();
  };
}
