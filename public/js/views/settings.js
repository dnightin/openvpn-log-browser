import { api } from "../api.js";
import { getTimeZone, setTimeZone, localTimeZone } from "../state.js";
import { esc } from "../util.js";

const TIME_ZONES = Array.from(new Set([
  localTimeZone, "UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles", "Europe/London"
]));

function zoneLabel(zone) {
  return zone === localTimeZone ? "Local (" + zone + ")" : zone;
}

export async function mount(root) {
  const selected = getTimeZone();
  const zones = TIME_ZONES.includes(selected) ? TIME_ZONES : [selected, ...TIME_ZONES];

  root.innerHTML =
    '<div class="view view-settings">' +
      '<header class="view-header"><h1>Settings</h1></header>' +
      '<div class="settings-page">' +
        '<section class="settings-section">' +
          "<h2>Display</h2>" +
          '<label class="wide">Timezone<select id="settingsTimeZone">' +
            zones.map((zone) => '<option value="' + esc(zone) + '"' + (zone === selected ? " selected" : "") + ">" + esc(zoneLabel(zone)) + "</option>").join("") +
          "</select></label>" +
        "</section>" +
        '<section class="settings-section">' +
          "<h2>Log source</h2>" +
          '<div class="settings-grid">' +
            '<label>Fetch mode<select name="sourceMode"><option value="http">HTTP bucket listing</option><option value="s3-api">S3 API with IAM credentials</option></select></label>' +
            '<label>AWS region<input name="sourceRegion" autocomplete="off" placeholder="us-east-1"></label>' +
            '<label class="wide">S3 bucket URL<input name="sourceBucketUrl" autocomplete="off" placeholder="https://bucket.s3.us-east-1.amazonaws.com/"></label>' +
            '<label>S3 bucket name<input name="sourceBucketName" autocomplete="off" placeholder="bucket-name"></label>' +
            '<label>Log prefix<input name="sourceLogPrefix" autocomplete="off" placeholder="CloudConnexa/wellesley/"></label>' +
            '<div class="muted wide" id="sourceCredentialStatus"></div>' +
          "</div>" +
        "</section>" +
        '<section class="settings-section">' +
          "<h2>SAML 2.0 SSO</h2>" +
          '<div class="settings-grid">' +
            '<label class="check-row"><input type="checkbox" name="enabled"> Enable SAML login</label>' +
            '<label class="check-row"><input type="checkbox" name="requireAuth"> Require SSO for API access</label>' +
            '<label>SP entity ID<input name="issuer" autocomplete="off"></label>' +
            '<label>SP ACS callback URL<input name="callbackUrl" autocomplete="off" placeholder="Auto-generated if blank"></label>' +
            '<label>IdP login URL<input name="entryPoint" autocomplete="off"></label>' +
            '<label>IdP logout URL<input name="logoutUrl" autocomplete="off"></label>' +
            '<label class="wide">Audience<input name="audience" autocomplete="off" placeholder="Defaults to SP entity ID"></label>' +
            '<label class="wide">IdP signing certificate<textarea name="idpCert" spellcheck="false" rows="5"></textarea></label>' +
            '<label class="check-row"><input type="checkbox" name="wantAssertionsSigned"> Require signed assertions</label>' +
            '<label class="check-row"><input type="checkbox" name="wantAuthnResponseSigned"> Require signed responses</label>' +
            '<label class="check-row wide"><input type="checkbox" name="disableRequestedAuthnContext"> Let the IdP choose auth context</label>' +
            '<label class="wide">SP metadata URL<input id="metadataUrl" readonly></label>' +
          "</div>" +
        "</section>" +
        '<div class="settings-actions">' +
          '<span class="status-line" id="settingsStatus"></span>' +
          '<button type="button" id="saveSettingsButton">Save settings</button>' +
        "</div>" +
      "</div>" +
    "</div>";

  const form = root.querySelector(".settings-page");
  const statusEl = root.querySelector("#settingsStatus");
  const sourceCredentialStatus = root.querySelector("#sourceCredentialStatus");
  const metadataUrl = root.querySelector("#metadataUrl");
  const timeZoneSelect = root.querySelector("#settingsTimeZone");

  async function load() {
    const source = await api.getSourceSettings();
    form.querySelector('[name="sourceMode"]').value = source.mode || "http";
    form.querySelector('[name="sourceBucketUrl"]').value = source.bucketUrl || "";
    form.querySelector('[name="sourceBucketName"]').value = source.bucketName || "";
    form.querySelector('[name="sourceRegion"]').value = source.region || "";
    form.querySelector('[name="sourceLogPrefix"]').value = source.logPrefix || "";
    sourceCredentialStatus.textContent = source.mode === "s3-api"
      ? (source.hasIamCredentialEnv ? "IAM credential environment detected." : "IAM credentials are read from the service environment or instance role.")
      : "HTTP mode uses bucket policy access.";

    const saml = await api.getSamlSettings();
    form.querySelector('[name="enabled"]').checked = Boolean(saml.enabled);
    form.querySelector('[name="requireAuth"]').checked = Boolean(saml.requireAuth);
    form.querySelector('[name="issuer"]').value = saml.issuer || "";
    form.querySelector('[name="callbackUrl"]').value = saml.callbackUrl || "";
    form.querySelector('[name="entryPoint"]').value = saml.entryPoint || "";
    form.querySelector('[name="logoutUrl"]').value = saml.logoutUrl || "";
    form.querySelector('[name="audience"]').value = saml.audience || "";
    form.querySelector('[name="idpCert"]').value = saml.idpCert || "";
    form.querySelector('[name="wantAssertionsSigned"]').checked = Boolean(saml.wantAssertionsSigned);
    form.querySelector('[name="wantAuthnResponseSigned"]').checked = Boolean(saml.wantAuthnResponseSigned);
    form.querySelector('[name="disableRequestedAuthnContext"]').checked = Boolean(saml.disableRequestedAuthnContext);
    metadataUrl.value = saml.metadataUrl || "";
  }

  async function save() {
    statusEl.className = "status-line";
    statusEl.textContent = "Saving...";
    setTimeZone(timeZoneSelect.value);
    try {
      await api.saveSourceSettings({
        mode: form.querySelector('[name="sourceMode"]').value,
        bucketUrl: form.querySelector('[name="sourceBucketUrl"]').value,
        bucketName: form.querySelector('[name="sourceBucketName"]').value,
        region: form.querySelector('[name="sourceRegion"]').value,
        logPrefix: form.querySelector('[name="sourceLogPrefix"]').value
      });
      await api.saveSamlSettings({
        enabled: form.querySelector('[name="enabled"]').checked,
        requireAuth: form.querySelector('[name="requireAuth"]').checked,
        issuer: form.querySelector('[name="issuer"]').value,
        callbackUrl: form.querySelector('[name="callbackUrl"]').value,
        entryPoint: form.querySelector('[name="entryPoint"]').value,
        logoutUrl: form.querySelector('[name="logoutUrl"]').value,
        audience: form.querySelector('[name="audience"]').value,
        idpCert: form.querySelector('[name="idpCert"]').value,
        wantAssertionsSigned: form.querySelector('[name="wantAssertionsSigned"]').checked,
        wantAuthnResponseSigned: form.querySelector('[name="wantAuthnResponseSigned"]').checked,
        disableRequestedAuthnContext: form.querySelector('[name="disableRequestedAuthnContext"]').checked
      });
      statusEl.textContent = "Settings saved.";
      await load();
    } catch (error) {
      statusEl.className = "status-line error";
      statusEl.textContent = error.message;
    }
  }

  function onSaveClick() { save().catch(console.error); }
  root.querySelector("#saveSettingsButton").addEventListener("click", onSaveClick);

  await load().catch((error) => {
    statusEl.className = "status-line error";
    statusEl.textContent = error.message;
  });

  return () => {
    root.querySelector("#saveSettingsButton").removeEventListener("click", onSaveClick);
  };
}
