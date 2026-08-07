const TIME_ZONE_STORAGE_KEY = "openvpnLogBrowserTimeZone";
const COLUMN_WIDTH_STORAGE_KEY = "openvpnLogBrowserColumnWidths";
const SAVED_VIEWS_STORAGE_KEY = "openvpnLogBrowserSavedViews";

export const localTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";

export function validTimeZone(zone) {
  try {
    Intl.DateTimeFormat([], { timeZone: zone }).format(new Date());
    return zone;
  } catch {
    return localTimeZone;
  }
}

export function getTimeZone() {
  return validTimeZone(localStorage.getItem(TIME_ZONE_STORAGE_KEY) || localTimeZone);
}

export function setTimeZone(zone) {
  localStorage.setItem(TIME_ZONE_STORAGE_KEY, validTimeZone(zone));
}

export const defaultColumnWidths = { time: 190, user: 200, event: 140, device: 200, ip: 220, gateway: 200, duration: 95, transfer: 100 };
export const minColumnWidths = { time: 140, user: 120, event: 100, device: 140, ip: 150, gateway: 140, duration: 80, transfer: 85 };

export function loadColumnWidths() {
  try {
    return { ...defaultColumnWidths, ...JSON.parse(localStorage.getItem(COLUMN_WIDTH_STORAGE_KEY) || "{}") };
  } catch {
    return { ...defaultColumnWidths };
  }
}

export function saveColumnWidths(widths) {
  localStorage.setItem(COLUMN_WIDTH_STORAGE_KEY, JSON.stringify(widths));
}

export function loadSavedViews() {
  try {
    const parsed = JSON.parse(localStorage.getItem(SAVED_VIEWS_STORAGE_KEY) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveSavedViews(views) {
  localStorage.setItem(SAVED_VIEWS_STORAGE_KEY, JSON.stringify(views));
}

let authState = { authenticated: false, name: "", email: "", source: "none" };

export function getAuthState() {
  return authState;
}

export function setAuthState(next) {
  authState = next || authState;
}
