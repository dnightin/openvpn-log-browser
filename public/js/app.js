import { api } from "./api.js";
import { setAuthState } from "./state.js";
import { registerRoute, startRouter } from "./router.js";
import * as dashboard from "./views/dashboard.js";
import * as investigate from "./views/investigate.js";
import * as settings from "./views/settings.js";

registerRoute("dashboard", dashboard);
registerRoute("investigate", investigate);
registerRoute("settings", settings);

async function loadAuth() {
  const nameEl = document.querySelector("#navAccountName");
  const loginLink = document.querySelector("#navLoginLink");
  const logoutLink = document.querySelector("#navLogoutLink");
  try {
    const data = await api.getAuth();
    setAuthState(data.user);
    nameEl.textContent = data.user && data.user.authenticated ? (data.user.email || data.user.name || "Signed in") : "Not signed in";
    loginLink.style.display = data.saml && data.saml.ready ? "block" : "none";
    logoutLink.style.display = data.user && data.user.authenticated ? "block" : "none";
  } catch (error) {
    nameEl.textContent = "Not signed in";
    console.error(error);
  }
}

loadAuth();
startRouter();
