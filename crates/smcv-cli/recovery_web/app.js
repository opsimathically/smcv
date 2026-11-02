const main = document.querySelector("main");
const live = document.querySelector("#status");
let staged = null;

function el(tag, attributes = {}, children = []) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) {
    if (name === "text") node.textContent = value;
    else if (value !== null) node.setAttribute(name, value);
  }
  for (const child of children) node.append(child);
  return node;
}

function clear() { main.replaceChildren(); }
function announce(message) { live.textContent = ""; requestAnimationFrame(() => { live.textContent = message; }); }
function date(value) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "full", timeStyle: "long" }).format(new Date(value));
}
function field(label, input, help) {
  const id = input.id;
  const helpNode = help ? el("span", { class: "help", id: `${id}-help`, text: help }) : null;
  if (helpNode) input.setAttribute("aria-describedby", helpNode.id);
  return el("label", { for: id }, [el("span", { text: label }), input, ...(helpNode ? [helpNode] : [])]);
}
function heading(title, intro) {
  return [el("p", { class: "eyebrow", text: "Fresh-host recovery" }), el("h1", { text: title }), el("p", { text: intro })];
}

async function request(path, options) {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  const response = await fetch(path, { ...options, headers, credentials: "same-origin", cache: "no-store", redirect: "error" });
  let body = null;
  try { body = await response.json(); } catch (_error) { body = null; }
  if (!response.ok) throw new Error(body?.message || "The local recovery request failed.");
  return body;
}

function renderClaim() {
  clear();
  const code = el("input", { id: "authorization-code", type: "password", autocomplete: "off", inputmode: "text", maxlength: "64", required: "" });
  const error = el("p", { class: "error", role: "alert", hidden: "" });
  const submit = el("button", { type: "submit", text: "Authorize this browser" });
  const form = el("form", { class: "card stack" }, [
    field("Local recovery authorization code", code, "Copy the separate code displayed by the CLI. It is submitted once in the request body and never placed in a URL or browser storage."),
    error,
    el("div", { class: "actions" }, [submit]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault(); error.hidden = true; submit.disabled = true;
    const authorizationCode = code.value; code.value = "";
    try {
      await request("/api/recovery/claim", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ authorization_code: authorizationCode }),
      });
      renderUpload(); announce("Local browser authorized. Select the portable backup and separate archive key.");
    } catch (failure) {
      error.textContent = failure.message; error.hidden = false; submit.disabled = false; code.focus();
    }
  });
  main.append(...heading("Authorize local recovery", "This clean loopback URL needs the separate one-use code displayed by the CLI. The channel closes after ten minutes or one activation attempt."), form);
  code.focus();
}

function renderUpload() {
  clear();
  const archive = el("input", { id: "archive", type: "file", accept: ".smcvault,application/octet-stream", required: "" });
  const mode = el("select", { id: "key-mode" }, [el("option", { value: "generated_recovery", text: "Recovery key" }), el("option", { value: "passphrase", text: "Passphrase" })]);
  const key = el("input", { id: "key", type: "password", autocomplete: "off", maxlength: "4096", required: "" });
  const error = el("p", { class: "error", role: "alert", hidden: "" });
  const submit = el("button", { type: "submit", text: "Authenticate archive metadata" });
  const form = el("form", { class: "card stack" }, [
    field("Portable .smcvault file", archive, "The encrypted file is staged in a restrictive local temporary directory."),
    field("Backup key type", mode),
    field("Separate recovery key or passphrase", key, "The key remains only in this short-lived local process until activation."),
    el("div", { class: "callout" }, [el("strong", { text: "No destination is activated at this step." }), el("p", { text: "SMCV first authenticates the archive and shows its creation time and recovery epoch. You then choose how to handle application credentials." })]),
    error,
    el("div", { class: "actions" }, [submit]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.hidden = true;
    const file = archive.files?.[0];
    if (!file || !file.name.toLowerCase().endsWith(".smcvault")) {
      error.textContent = "Select a .smcvault portable backup file."; error.hidden = false; archive.focus(); return;
    }
    submit.disabled = true; submit.textContent = "Uploading and authenticating…";
    const data = new FormData();
    data.append("key_mode", mode.value); data.append("key", key.value); data.append("archive", file, file.name);
    key.value = "";
    try { staged = await request("/api/recovery/verify", { method: "POST", body: data }); renderConfirmation(); }
    catch (failure) { error.textContent = failure.message; error.hidden = false; submit.disabled = false; submit.textContent = "Authenticate archive metadata"; key.focus(); }
  });
  main.append(...heading("Restore a portable vault", "This loopback-only channel was authorized by the local CLI and expires after ten minutes."), form);
  archive.focus();
}

function renderConfirmation() {
  clear();
  const credentialMode = el("select", { id: "credential-mode" }, [
    el("option", { value: "preserve", text: "Preserve application credentials (disaster recovery)" }),
    el("option", { value: "revoke", text: "Revoke all application credentials (migration or uncertain compromise)" }),
  ]);
  const confirm = el("input", { id: "activate-confirm", type: "checkbox" });
  const error = el("p", { class: "error", role: "alert", hidden: "" });
  const activate = el("button", { class: "danger", type: "button", text: "Activate restored vault", disabled: "" });
  confirm.addEventListener("change", () => { activate.disabled = !confirm.checked; });
  activate.addEventListener("click", async () => {
    activate.disabled = true; activate.textContent = "Validating and activating…"; error.hidden = true;
    try {
      const report = await request("/api/recovery/activate", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ archive_id: staged.archive_id, credential_mode: credentialMode.value }),
      });
      renderComplete(report);
    } catch (failure) { error.textContent = `${failure.message} This single-use activation attempt is closed; restart the CLI ceremony before retrying.`; error.hidden = false; activate.textContent = "Activation attempt closed"; }
  });
  main.append(
    ...heading("Review authenticated backup", "The archive metadata below was authenticated with the separate recovery material. Activation has not started."),
    el("section", { class: "summary", "aria-label": "Authenticated archive summary" }, [
      el("div", {}, [el("strong", { text: "Created" }), el("span", { text: date(staged.created_at_unix_ms) })]),
      el("div", {}, [el("strong", { text: "Format" }), el("span", { text: `Version ${staged.format_version}` })]),
      el("div", {}, [el("strong", { text: "Records" }), el("span", { text: String(staged.record_count) })]),
      el("div", {}, [el("strong", { text: "Source recovery epoch" }), el("span", { text: String(staged.source_recovery_epoch) })]),
    ]),
    el("section", { class: "card stack" }, [
      el("p", { class: "mono", text: `Archive ${staged.archive_id}` }),
      el("p", { class: "mono", text: `Logical vault ${staged.logical_vault_id}` }),
      el("div", { class: "callout" }, [el("strong", { text: "Rollback and fork risk" }), el("p", { text: "An internally valid archive may be older than other copies. Decommission the old installation. After uncertain compromise, revoke credentials and rotate upstream secrets based on exposure analysis." })]),
      field("Application credential handling", credentialMode, "Preserve keeps verifier-only credentials working. Revoke is safer for migration or possible compromise."),
      el("label", { for: confirm.id }, [confirm, el("span", { text: "I understand activation creates a new installation and recovery epoch at the CLI-selected paths." })]),
      error,
      el("div", { class: "actions" }, [activate]),
    ]),
  );
  credentialMode.focus(); announce("Archive authenticated. Review its metadata and activation choices.");
}

function renderComplete(report) {
  clear(); staged = null;
  main.append(
    ...heading("Restored vault is ready", "Activation completed atomically. This recovery channel is closing and cannot be reused."),
    el("section", { class: "summary", "aria-label": "Restore result" }, [
      el("div", {}, [el("strong", { text: "Recovery epoch" }), el("span", { text: String(report.recovery_epoch) })]),
      el("div", {}, [el("strong", { text: "Imported records" }), el("span", { text: String(report.imported_records) })]),
      el("div", {}, [el("strong", { text: "Imported audit events" }), el("span", { text: String(report.imported_audit_events) })]),
      el("div", {}, [el("strong", { text: "Revoked app credentials" }), el("span", { text: String(report.revoked_application_credentials) })]),
    ]),
    el("section", { class: "card" }, [
      el("p", { class: "mono", text: `Vault ${report.vault_id}` }), el("p", { class: "mono", text: `Installation ${report.installation_id}` }),
      el("p", { text: `${report.disabled_source_bound_authenticators} source-bound passkey authenticator(s) were disabled. Sign in with the restored owner password, then enroll destination passkeys.` }),
      el("p", { text: "Next: start the normal SMCV server, review audit epochs and application access, decommission the source installation, and create a new portable backup." }),
    ]),
  );
  main.focus(); announce("Restore activation completed. The vault is ready.");
}

renderClaim();
