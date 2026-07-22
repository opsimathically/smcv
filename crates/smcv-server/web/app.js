import { ApiClient, ApiFailure } from "/assets/api.js";

const api = new ApiClient();
const loginView = document.querySelector("#login-view");
const appView = document.querySelector("#app-view");
const loginForm = document.querySelector("#login-form");
const loginError = document.querySelector("#login-error");
const passwordInput = document.querySelector("#password");
const page = document.querySelector("#page");
const main = document.querySelector("#main-content");
const pageStatus = document.querySelector("#page-status");
const globalStatus = document.querySelector("#global-status");
const sidebar = document.querySelector("#primary-navigation");
const navToggle = document.querySelector("#nav-toggle");
const skipLink = document.querySelector("#skip-link");
const routes = new Set(["overview", "secrets", "applications", "access", "activity", "backups", "settings"]);
let toastTimer = null;
let sensitiveViewCleared = false;

function element(tag, attributes = {}, children = []) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) {
    if (name === "className") node.className = value;
    else if (name === "text") node.textContent = value;
    else if (name.startsWith("on") && typeof value === "function") node.addEventListener(name.slice(2).toLowerCase(), value);
    else if (value !== null && value !== undefined) node.setAttribute(name, String(value));
  }
  for (const child of children) node.append(child);
  return node;
}

function clear(node) {
  for (const control of node.querySelectorAll("[data-clear-sensitive]")) control.click();
  node.replaceChildren();
}

function formatError(error, action) {
  if (error instanceof ApiFailure && error.status >= 400 && error.status < 500) {
    const request = error.requestId ? ` Request ID: ${error.requestId}` : "";
    return `${action} No change was committed. ${error.message}${request}`;
  }
  const request = error instanceof ApiFailure && error.requestId ? ` Request ID: ${error.requestId}` : "";
  return `${action} SMCV could not confirm the final state. Reload current state before retrying any change.${request}`;
}

function outcomeKnownNotCommitted(error) {
  return error instanceof ApiFailure && error.status >= 400 && error.status < 500;
}

function announce(message) {
  pageStatus.textContent = "";
  requestAnimationFrame(() => { pageStatus.textContent = message; });
}

function toast(message) {
  globalStatus.textContent = message;
  globalStatus.hidden = false;
  if (toastTimer) window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    globalStatus.hidden = true;
    globalStatus.textContent = "";
  }, 5000);
}

function decodeBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  return bytes.buffer;
}

function encodeBase64Url(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function publicKeyRequest(options) {
  const request = structuredClone(options.publicKey || options);
  request.challenge = decodeBase64Url(request.challenge);
  if (Array.isArray(request.allowCredentials)) {
    request.allowCredentials = request.allowCredentials.map((credential) => ({
      ...credential,
      id: decodeBase64Url(credential.id),
    }));
  }
  return request;
}

function publicKeyCreation(options) {
  const creation = structuredClone(options.publicKey || options);
  creation.challenge = decodeBase64Url(creation.challenge);
  creation.user.id = decodeBase64Url(creation.user.id);
  if (Array.isArray(creation.excludeCredentials)) {
    creation.excludeCredentials = creation.excludeCredentials.map((credential) => ({
      ...credential,
      id: decodeBase64Url(credential.id),
    }));
  }
  return creation;
}

function authenticationResponse(credential) {
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: encodeBase64Url(credential.response.authenticatorData),
      clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
      signature: encodeBase64Url(credential.response.signature),
      userHandle: credential.response.userHandle ? encodeBase64Url(credential.response.userHandle) : null,
    },
    extensions: credential.getClientExtensionResults(),
  };
}

function registrationResponse(credential) {
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: encodeBase64Url(credential.response.attestationObject),
      clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
      transports: typeof credential.response.getTransports === "function" ? credential.response.getTransports() : [],
    },
    extensions: credential.getClientExtensionResults(),
  };
}

function pageHeader(eyebrow, title, description, actions = []) {
  return element("header", { className: "page-header" }, [
    element("div", { className: "page-heading" }, [
      element("div", { className: "eyebrow", text: eyebrow }),
      element("h1", { text: title }),
      element("p", { className: "lede", text: description }),
    ]),
    element("div", { className: "page-actions" }, actions),
  ]);
}

function metricCard(title, value, status, statusClass = "neutral") {
  return element("section", { className: "card" }, [
    element("div", { className: "card-header" }, [
      element("h2", { text: title }),
      element("span", { className: `badge ${statusClass}`, text: status }),
    ]),
    element("div", { className: "metric", text: value }),
  ]);
}

function loadingState(label) {
  return element("section", { className: "card", "aria-busy": "true" }, [
    element("h2", { text: label }),
    element("p", { className: "muted", text: "Loading bounded metadata…" }),
  ]);
}

function formField(label, input, help = null) {
  const children = [element("label", { for: input.id, text: label }), input];
  if (help) {
    const helpId = `${input.id}-help`;
    input.setAttribute("aria-describedby", helpId);
    children.push(element("p", { id: helpId, className: "field-help", text: help }));
  }
  return element("div", { className: "field" }, children);
}

function formError() {
  return element("p", { className: "form-message error", role: "alert", tabindex: "-1", hidden: "" });
}

function showFormError(node, error, action) {
  node.textContent = formatError(error, action);
  node.hidden = false;
  node.focus?.();
}

function utf8Base64(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  }
  return btoa(binary);
}

function displaySecretValue(encoded) {
  const binary = atob(encoded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  try {
    return { value: new TextDecoder("utf-8", { fatal: true }).decode(bytes), encoding: "UTF-8 text" };
  } catch (_error) {
    return { value: encoded, encoding: "Base64 (binary value)" };
  }
}

function formatDate(unixMilliseconds) {
  if (unixMilliseconds === null || unixMilliseconds === undefined) return "Not set";
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short",
  }).format(new Date(unixMilliseconds));
}

function confirmAction(title, description, actionLabel, level = "Danger") {
  const dialog = document.querySelector("#confirm-dialog");
  document.querySelector("#confirm-title").textContent = title;
  document.querySelector("#confirm-description").textContent = description;
  document.querySelector("#confirm-level").textContent = level;
  document.querySelector("#confirm-action").textContent = actionLabel;
  dialog.showModal();
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), { once: true });
  });
}

async function loadNamespaceTree() {
  const output = [];
  const queue = [{ parent: null, depth: 0, path: [] }];
  while (queue.length > 0 && output.length < 1000) {
    const current = queue.shift();
    let after = null;
    do {
      const query = new URLSearchParams({ limit: "100" });
      if (current.parent) query.set("parent_namespace_id", current.parent);
      if (after) query.set("after", after);
      const pageData = await api.request(`/namespaces?${query}`);
      for (const namespace of pageData.namespaces) {
        const path = [...current.path, namespace.metadata.name];
        const item = { ...namespace, parent: current.parent, depth: current.depth, path };
        output.push(item);
        if (current.depth < 32 && output.length < 1000) {
          queue.push({ parent: namespace.id, depth: current.depth + 1, path });
        }
      }
      after = pageData.next_after;
    } while (after && output.length < 1000);
  }
  return output;
}

function namespaceOption(namespace) {
  return element("option", {
    value: namespace.id,
    text: `${"— ".repeat(namespace.depth)}${namespace.path.join(" / ")}`,
  });
}

async function renderNamespaceCreate(namespaces) {
  clear(page);
  const name = element("input", { id: "namespace-name", name: "name", required: "", maxlength: "256", autocomplete: "off" });
  const description = element("textarea", { id: "namespace-description", name: "description", maxlength: "4096" });
  const parent = element("select", { id: "namespace-parent", name: "parent" }, [
    element("option", { value: "", text: "Top level" }),
    ...namespaces.map(namespaceOption),
  ]);
  const error = formError();
  let idempotencyKey = crypto.randomUUID();
  const form = element("form", { className: "card stack", novalidate: "" }, [
    element("h2", { text: "Namespace details" }),
    formField("Name", name, "Names are protected metadata and are never used as URLs."),
    formField("Description (optional)", description),
    formField("Parent namespace", parent, "Moving later may change inherited application access."),
    error,
    element("div", { className: "page-actions" }, [
      element("button", { className: "button primary", type: "submit", text: "Create namespace" }),
      element("button", { className: "button secondary", type: "button", text: "Cancel", onclick: renderSecrets }),
    ]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.hidden = true;
    const submit = form.querySelector("button[type='submit']");
    submit.disabled = true;
    try {
      await api.request("/namespaces", {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey },
        body: {
          parent_namespace_id: parent.value || null,
          metadata: { name: name.value, description: description.value || null, username: null, tags: [] },
        },
      });
      toast("Namespace created.");
      await renderSecrets();
    } catch (requestError) {
      showFormError(error, requestError, "SMCV could not create this namespace.");
      if (outcomeKnownNotCommitted(requestError)) idempotencyKey = crypto.randomUUID();
      submit.disabled = false;
    }
  });
  page.append(
    pageHeader("Protected structure", "Create namespace", "Namespaces organize secrets and define inherited policy boundaries."),
    form,
  );
  name.focus();
}

async function renderSecretCreate(namespaces, preferredNamespace = null) {
  clear(page);
  const namespace = element("select", { id: "secret-namespace", name: "namespace", required: "" }, namespaces.map(namespaceOption));
  if (preferredNamespace) namespace.value = preferredNamespace;
  const name = element("input", { id: "secret-name", name: "name", required: "", maxlength: "256", autocomplete: "off" });
  const username = element("input", { id: "secret-username", name: "username", maxlength: "512", autocomplete: "off" });
  const description = element("textarea", { id: "secret-description", name: "description", maxlength: "4096" });
  const value = element("textarea", { id: "secret-value", name: "value", required: "", maxlength: "1048576", autocomplete: "off", spellcheck: "false" });
  const error = formError();
  let idempotencyKey = crypto.randomUUID();
  const form = element("form", { className: "card stack", novalidate: "" }, [
    element("h2", { text: "Secret details" }),
    formField("Namespace", namespace, "Existing namespace policies may grant applications access to this new secret."),
    formField("Display name", name),
    formField("Username or account (optional)", username),
    formField("Description (optional)", description),
    formField("Secret value", value, "Saving creates immutable version 1. The value field is cleared after the request."),
    error,
    element("div", { className: "page-actions" }, [
      element("button", { className: "button primary", type: "submit", text: "Create version 1" }),
      element("button", { className: "button secondary", type: "button", text: "Cancel", onclick: renderSecrets }),
    ]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.hidden = true;
    const submit = form.querySelector("button[type='submit']");
    submit.disabled = true;
    const encodedValue = utf8Base64(value.value);
    value.value = "";
    try {
      const created = await api.request("/secrets", {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey },
        body: {
          namespace_id: namespace.value,
          metadata: {
            name: name.value,
            description: description.value || null,
            username: username.value || null,
            tags: [],
          },
          value_base64: encodedValue,
          expires_at_unix_ms: null,
          rotation_due_at_unix_ms: null,
        },
      });
      toast("Secret version 1 created. The value field was cleared.");
      await renderSecretDetail({
        id: created.id,
        metadata: { name: name.value, description: description.value || null, username: username.value || null, tags: [] },
        current_version: created.version,
        revision: created.revision,
        namespace_id: namespace.value,
      }, namespaces);
    } catch (requestError) {
      showFormError(error, requestError, "SMCV could not create this secret.");
      if (outcomeKnownNotCommitted(requestError)) idempotencyKey = crypto.randomUUID();
      submit.disabled = false;
      value.focus();
    }
  });
  page.append(
    pageHeader("New protected record", "Create secret", "The value is sent only in this request and is not placed in a URL, browser storage, or page history."),
    form,
  );
  name.focus();
}

async function revealInto(secretId, version, container, button) {
  button.disabled = true;
  button.textContent = "Revealing…";
  try {
    const path = version === null ? `/secrets/${secretId}/value` : `/secrets/${secretId}/versions/${version}/value`;
    const response = await api.request(path);
    const decoded = displaySecretValue(response.value_base64);
    const mask = container.querySelector(".secret-mask");
    if (mask) mask.hidden = true;
    const value = element("code", { className: "secret-value", "data-revealed-secret": "", text: decoded.value });
    const encoding = element("span", { className: "badge warning", text: `Revealed · ${decoded.encoding}` });
    const hide = element("button", { className: "button secondary", type: "button", text: "Hide value", "data-clear-sensitive": "" });
    const copy = element("button", { className: "button secondary", type: "button", text: "Copy value" });
    const exposureTimer = window.setTimeout(() => hide.click(), 60_000);
    hide.addEventListener("click", () => {
      window.clearTimeout(exposureTimer);
      value.remove();
      encoding.remove();
      hide.remove();
      copy.remove();
      button.hidden = false;
      button.disabled = false;
      button.textContent = "Reveal value";
      if (mask) mask.hidden = false;
      button.focus();
      announce("Secret value hidden and removed from the document.");
    });
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(decoded.value);
        toast("Copied to clipboard. Other applications or clipboard managers may retain it.");
      } catch (_error) {
        toast("SMCV could not copy the value. The revealed value remains available for manual selection.");
      }
    });
    button.hidden = true;
    container.append(encoding, value, element("div", { className: "page-actions" }, [hide, copy]));
    announce("Secret value revealed for up to one minute. It has not been read aloud automatically.");
    hide.focus();
  } catch (error) {
    button.disabled = false;
    button.textContent = "Reveal value";
    toast(formatError(error, "SMCV could not reveal this value."));
  }
}

async function renderSecretUpdate(secret, namespaces) {
  clear(page);
  const value = element("textarea", { id: "new-secret-value", required: "", maxlength: "1048576", autocomplete: "off", spellcheck: "false" });
  const error = formError();
  const submit = element("button", { className: "button primary", type: "submit", text: `Create version ${secret.current_version + 1}` });
  const form = element("form", { className: "card stack" }, [
    element("h2", { text: "New immutable value" }),
    formField("Secret value", value, `This request expects current version ${secret.current_version} and revision ${secret.revision}. It never overwrites prior versions.`),
    element("div", { className: "callout warning" }, [
      element("strong", { text: "Concurrent changes fail safely." }),
      element("p", { text: "If another update wins first, SMCV rejects this stale save and clears this secret input. Review the newer version before entering a value again." }),
    ]),
    error,
    element("div", { className: "page-actions" }, [submit, element("button", { className: "button secondary", type: "button", text: "Cancel", onclick: () => renderSecretDetail(secret, namespaces) })]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    error.hidden = true;
    const encoded = utf8Base64(value.value);
    value.value = "";
    try {
      const updated = await api.request(`/secrets/${secret.id}`, {
        method: "PUT",
        body: {
          expected_current_version: secret.current_version,
          expected_revision: secret.revision,
          value_base64: encoded,
          expires_at_unix_ms: null,
          rotation_due_at_unix_ms: null,
        },
      });
      toast(`Secret version ${updated.version} created. Earlier versions remain available.`);
      await renderSecretDetail({ ...secret, current_version: updated.version, revision: secret.revision + 1 }, namespaces);
    } catch (requestError) {
      showFormError(error, requestError, "SMCV could not create the new version. The secret input was cleared; reload the record before retrying if another update changed it.");
      submit.textContent = "Reload before retrying";
      form.querySelector(".page-actions").prepend(element("button", { className: "button primary", type: "button", text: "Reload secret list", onclick: renderSecrets }));
    }
  });
  page.append(pageHeader("Immutable history", `Update ${secret.metadata.name}`, "A successful save appends a new version; it never edits an existing value."), form);
  value.focus();
}

async function renderSecretDetail(secret, namespaces) {
  clear(page);
  const valueArea = element("section", { className: "card" }, [
    element("div", { className: "card-header" }, [
      element("h2", { text: "Current value" }),
      element("span", { className: "badge neutral", text: "Not revealed" }),
    ]),
    element("div", { className: "secret-value secret-mask", "aria-label": "Secret value hidden", text: "••••••••••••" }),
  ]);
  const reveal = element("button", { className: "button primary", type: "button", text: "Reveal value" });
  reveal.addEventListener("click", () => revealInto(secret.id, null, valueArea, reveal));
  valueArea.append(reveal);
  const archive = element("button", { className: "button secondary", type: "button", text: "Archive secret" });
  archive.addEventListener("click", async () => {
    const confirmed = await confirmAction(
      "Archive this secret?",
      "Applications will no longer be able to use this active secret. Immutable versions remain in the vault and the owner may restore it later.",
      "Archive secret",
      "Warning",
    );
    if (!confirmed) return;
    try {
      await api.request(`/secrets/${secret.id}/archive`, { method: "POST", body: { expected_revision: secret.revision } });
      toast("Secret archived. Its retained versions were not purged.");
      await renderSecrets();
    } catch (error) {
      toast(formatError(error, "SMCV could not archive this secret."));
    }
  });
  const remove = element("button", { className: "button danger", type: "button", text: "Delete secret" });
  remove.addEventListener("click", async () => {
    const confirmed = await confirmAction(
      "Delete this secret?",
      "Delete tombstones this record and removes it from ordinary use. Its encrypted versions remain in the current vault until a separate purge, and prior backups or storage remnants may still contain encrypted data.",
      "Delete secret",
      "Danger",
    );
    if (!confirmed) return;
    try {
      await api.request(`/secrets/${secret.id}/delete`, { method: "POST", body: { expected_revision: secret.revision } });
      toast("Secret deleted and retained as a tombstone. Its encrypted history was not purged.");
      await renderSecrets();
    } catch (error) {
      toast(formatError(error, "SMCV could not delete this secret."));
    }
  });
  page.append(
    pageHeader("Secret metadata", secret.metadata.name, `Current immutable version ${secret.current_version}. The value has not been fetched.`, [
      element("button", { className: "button secondary", type: "button", text: "Back to secrets", onclick: renderSecrets }),
      element("button", { className: "button primary", type: "button", text: "Add new version", onclick: () => renderSecretUpdate(secret, namespaces) }),
      archive,
      remove,
    ]),
    element("div", { className: "grid cards" }, [
      element("section", { className: "card" }, [
        element("h2", { text: "Metadata" }),
        element("p", { text: secret.metadata.description || "No description" }),
        element("p", { className: "muted", text: secret.metadata.username ? `Account: ${secret.metadata.username}` : "No account name" }),
      ]),
      valueArea,
    ]),
    loadingState("Version history"),
  );
  try {
    const history = await api.request(`/secrets/${secret.id}/versions?limit=100`);
    const historyCard = element("section", { className: "card" }, [element("h2", { text: "Immutable versions" })]);
    for (const version of history.versions) {
      const area = element("div", { className: "data-row" }, [
        element("div", { className: "data-row-title", text: `Version ${version.version}` }),
        element("div", { className: "data-row-meta", text: formatDate(version.created_at_unix_ms) }),
      ]);
      const button = element("button", { className: "button secondary", type: "button", text: "Reveal value" });
      button.addEventListener("click", () => revealInto(secret.id, version.version, area, button));
      area.append(button);
      historyCard.append(area);
    }
    page.lastElementChild.replaceWith(historyCard);
  } catch (error) {
    page.lastElementChild.replaceWith(element("p", { className: "form-message error", role: "alert", text: formatError(error, "SMCV could not load version history.") }));
  }
}

async function changeSecretLifecycle(secret, state, namespace, namespaces, listContainer) {
  if (state === "archived") {
    const confirmed = await confirmAction(
      "Restore this secret?",
      "Restore returns this retained secret to active use. Existing application policies may permit access immediately.",
      "Restore secret",
      "Warning",
    );
    if (!confirmed) return;
    try {
      await api.request(`/secrets/${secret.id}/restore`, { method: "POST", body: { expected_revision: secret.revision } });
      toast("Secret restored to active use.");
      await renderSecretList(namespace, namespaces, listContainer, state);
    } catch (error) {
      toast(formatError(error, "SMCV could not restore this secret."));
    }
    return;
  }
  const confirmed = await confirmAction(
    "Purge current-vault ciphertext?",
    "Purge physically removes this secret's encrypted versions from the current vault after its recorded deletion time. The opaque tombstone and audit history remain. Prior backups or storage remnants may still contain encrypted data; this does not erase them everywhere.",
    "Purge current-vault ciphertext",
    "Danger",
  );
  if (!confirmed) return;
  try {
    await api.request(`/secrets/${secret.id}/purge`, {
      method: "POST",
      body: { expected_revision: secret.revision, retention_cutoff_unix_ms: Date.now() },
    });
    toast("Current-vault ciphertext purged. The tombstone, audit history, and any prior backup copies remain.");
    await renderSecretList(namespace, namespaces, listContainer, state);
  } catch (error) {
    toast(formatError(error, "SMCV could not purge this secret. Its retention preconditions may not be satisfied."));
  }
}

async function renderSecretList(namespace, namespaces, listContainer, state = "active") {
  clear(listContainer);
  listContainer.append(loadingState(`${state} secrets in ${namespace.path.join(" / ")}`));
  try {
    const query = new URLSearchParams({ namespace_id: namespace.id, limit: "100" });
    if (state !== "active") query.set("state", state);
    const endpoint = state === "active" ? "/secrets" : "/secrets/lifecycle";
    const response = await api.request(`${endpoint}?${query}`);
    clear(listContainer);
    if (response.secrets.length === 0) {
      listContainer.append(element("section", { className: "empty-state" }, [
        element("h2", { text: `No ${state} secrets in this namespace` }),
        element("p", { className: "muted", text: state === "active" ? "Create a secret to add immutable version 1. Archived and deleted records are kept in their separate views." : `Records in the ${state} lifecycle state will appear here.` }),
        ...(state === "active" ? [element("button", { className: "button primary", type: "button", text: "Create secret", onclick: () => renderSecretCreate(namespaces, namespace.id) })] : []),
      ]));
      return;
    }
    const rows = element("div", { className: "data-list", "aria-label": `${state} secrets in ${namespace.path.join(" / ")}` });
    for (const secret of response.secrets) {
      secret.namespace_id = namespace.id;
      let action;
      if (state === "active") {
        action = element("button", { className: "button secondary", type: "button", text: "Open", onclick: () => renderSecretDetail(secret, namespaces) });
      } else {
        action = element("button", {
          className: state === "deleted" ? "button danger" : "button secondary",
          type: "button",
          text: state === "archived" ? "Restore" : "Purge ciphertext",
          onclick: () => changeSecretLifecycle(secret, state, namespace, namespaces, listContainer),
        });
      }
      rows.append(element("div", { className: "data-row" }, [
        element("div", {}, [
          element("div", { className: "data-row-title", text: secret.metadata.name }),
          element("div", { className: "data-row-meta", text: secret.metadata.description || "No description" }),
        ]),
        element("div", { className: "data-row-meta", text: state === "deleted" ? `Deleted ${formatDate(secret.deleted_at_unix_ms)}` : `Version ${secret.current_version}` }),
        action,
      ]));
    }
    listContainer.append(rows);
  } catch (error) {
    clear(listContainer);
    listContainer.append(element("p", { className: "form-message error", role: "alert", text: formatError(error, "SMCV could not load secrets.") }));
  }
}

async function renderSecrets() {
  clear(page);
  page.append(pageHeader("Protected records", "Secrets", "Metadata is loaded without fetching plaintext values."), loadingState("Namespace structure"));
  try {
    const namespaces = await loadNamespaceTree();
    const actions = [
      element("button", { className: "button secondary", type: "button", text: "Create namespace", onclick: () => renderNamespaceCreate(namespaces) }),
    ];
    if (namespaces.length > 0) {
      actions.unshift(element("button", { className: "button primary", type: "button", text: "Create secret", onclick: () => renderSecretCreate(namespaces) }));
    }
    clear(page);
    page.append(pageHeader("Protected records", "Secrets", "Metadata is loaded without fetching plaintext values.", actions));
    if (namespaces.length === 0) {
      page.append(element("section", { className: "empty-state" }, [
        element("h2", { text: "Create the first namespace" }),
        element("p", { className: "muted", text: "A namespace is required before adding a secret and becomes a policy boundary." }),
        element("button", { className: "button primary", type: "button", text: "Create namespace", onclick: () => renderNamespaceCreate(namespaces) }),
      ]));
      return;
    }
    const selector = element("select", { id: "namespace-filter", "aria-label": "Namespace" }, namespaces.map(namespaceOption));
    const lifecycle = element("select", { id: "secret-lifecycle-filter", "aria-label": "Lifecycle state" }, [
      element("option", { value: "active", text: "Active" }),
      element("option", { value: "archived", text: "Archived" }),
      element("option", { value: "deleted", text: "Deleted" }),
    ]);
    const listContainer = element("div");
    const refresh = () => {
      const selected = namespaces.find((namespace) => namespace.id === selector.value);
      if (selected) renderSecretList(selected, namespaces, listContainer, lifecycle.value);
    };
    selector.addEventListener("change", refresh);
    lifecycle.addEventListener("change", refresh);
    page.append(element("section", { className: "card" }, [
      element("h2", { text: "Inventory view" }),
      formField("Namespace", selector),
      formField("Lifecycle state", lifecycle, "Archive is reversible. Delete creates a retained tombstone. Purge removes ciphertext only from the current vault."),
    ]), listContainer);
    await renderSecretList(namespaces[0], namespaces, listContainer, lifecycle.value);
  } catch (error) {
    clear(page);
    page.append(
      pageHeader("Protected records", "Secrets", "Metadata is loaded without fetching plaintext values."),
      element("p", { className: "form-message error", role: "alert", text: formatError(error, "SMCV could not load namespace metadata.") }),
    );
  }
}

async function loadApplications() {
  const applications = [];
  let after = null;
  do {
    const query = new URLSearchParams({ limit: "100" });
    if (after) query.set("after", after);
    const response = await api.request(`/service-identities?${query}`);
    applications.push(...response.applications);
    after = response.next_after;
  } while (after && applications.length < 1000);
  return applications;
}

async function renderApplicationCreate() {
  clear(page);
  const label = element("input", { id: "application-label", required: "", maxlength: "128", autocomplete: "off" });
  const description = element("textarea", { id: "application-description", maxlength: "2048" });
  const error = formError();
  const form = element("form", { className: "card stack", novalidate: "" }, [
    element("h2", { text: "Workload identity" }),
    formField("Application label", label, "Use one identity for one workload boundary, not one shared identity for an organization."),
    formField("Description (optional)", description),
    error,
    element("div", { className: "page-actions" }, [
      element("button", { className: "button primary", type: "submit", text: "Create application identity" }),
      element("button", { className: "button secondary", type: "button", text: "Cancel", onclick: renderApplications }),
    ]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = form.querySelector("button[type='submit']");
    submit.disabled = true;
    try {
      const created = await api.request("/service-identities", {
        method: "POST",
        body: { label: label.value, description: description.value || null },
      });
      toast("Application identity created without a credential or access policy.");
      await renderApplicationDetail({
        id: created.id,
        label: label.value,
        description: description.value || null,
        state: "active",
        revision: 1,
      });
    } catch (requestError) {
      showFormError(error, requestError, "SMCV could not create this application identity.");
      submit.disabled = false;
    }
  });
  page.append(
    pageHeader("Least privilege", "Create application", "The identity starts with no credentials and no access. Both must be granted explicitly."),
    form,
  );
  label.focus();
}

function credentialStatus(credential) {
  if (credential.revoked_at_unix_ms !== null) return ["Revoked", "danger"];
  if (credential.expires_at_unix_ms !== null && credential.expires_at_unix_ms <= Date.now()) return ["Expired", "warning"];
  return ["Active", "success"];
}

function showIssuedCredential(application, issued) {
  clear(page);
  const raw = element("code", { className: "secret-value", "data-revealed-secret": "", tabindex: "0", "aria-label": "Display-once application credential", text: issued.credential });
  const acknowledged = element("input", { id: "credential-acknowledged", type: "checkbox" });
  const continueButton = element("button", { className: "button primary", type: "button", text: "I stored this credential", disabled: "" });
  acknowledged.addEventListener("change", () => { continueButton.disabled = !acknowledged.checked; });
  continueButton.addEventListener("click", () => {
    raw.remove();
    renderApplicationDetail(application);
  });
  const copy = element("button", { className: "button secondary", type: "button", text: "Copy credential" });
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(issued.credential);
      toast("Copied to clipboard. Other applications or clipboard managers may retain it.");
    } catch (_error) {
      toast("SMCV could not copy the credential. Select the displayed credential manually.");
    }
  });
  page.append(
    pageHeader("Display once", "Store the new credential now", "SMCV stores only a verifier and cannot show this credential again."),
    element("section", { className: "card" }, [
      element("span", { className: "badge warning", text: "Revealed once" }),
      raw,
      element("p", { className: "muted", text: `Credential record ${issued.id}. Expiration: ${formatDate(issued.expires_at_unix_ms)}.` }),
      copy,
      element("label", { className: "checkbox-row", for: acknowledged.id }, [
        acknowledged,
        element("span", { text: "I stored this credential in the application’s protected configuration." }),
      ]),
      continueButton,
    ]),
  );
  raw.focus?.();
}

async function issueCredential(application) {
  clear(page);
  const expires = element("input", { id: "credential-expiry", type: "datetime-local" });
  const error = formError();
  const form = element("form", { className: "card stack" }, [
    element("h2", { text: "Credential lifetime" }),
    formField("Expiration (optional)", expires, "Use overlap during rotation, then revoke the older credential after the application uses the new one."),
    element("div", { className: "callout warning" }, [
      element("strong", { text: "The raw credential appears once." }),
      element("p", { text: "Copy it directly into protected application configuration. Do not put it in source code or a URL." }),
    ]),
    error,
    element("div", { className: "page-actions" }, [
      element("button", { className: "button primary", type: "submit", text: "Issue credential" }),
      element("button", { className: "button secondary", type: "button", text: "Cancel", onclick: () => renderApplicationDetail(application) }),
    ]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = form.querySelector("button[type='submit']");
    submit.disabled = true;
    const expiration = expires.value ? new Date(expires.value).getTime() : null;
    try {
      const issued = await api.request(`/service-identities/${application.id}/credentials`, {
        method: "POST",
        body: { expires_at_unix_ms: expiration },
      });
      showIssuedCredential(application, issued);
    } catch (requestError) {
      showFormError(error, requestError, "SMCV could not issue this credential.");
      submit.disabled = false;
    }
  });
  page.append(
    pageHeader("Credential rotation", `Issue credential for ${application.label}`, "Issuing a credential does not grant access; current policy bindings determine authority."),
    form,
  );
  expires.focus();
}

async function renderApplicationDetail(application) {
  clear(page);
  page.append(
    pageHeader("Workload identity", application.label, application.description || "No description", [
      element("button", { className: "button secondary", type: "button", text: "Back to applications", onclick: renderApplications }),
      element("button", { className: "button primary", type: "button", text: "Issue credential", onclick: () => issueCredential(application) }),
    ]),
    element("div", { className: "grid cards" }, [
      metricCard("Identity state", application.state === "active" ? "Active" : "Disabled", application.state, application.state === "active" ? "success" : "warning"),
      metricCard("Effective access", "Policy-derived", "Review by resource", "neutral"),
    ]),
    loadingState("Application credentials"),
  );
  try {
    const credentials = await api.request(`/service-identities/${application.id}/credentials?limit=100`);
    const section = element("section", { className: "card" }, [
      element("div", { className: "card-header" }, [
        element("h2", { text: "Credentials" }),
        element("span", { className: "badge neutral", text: `${credentials.credentials.length} records` }),
      ]),
    ]);
    if (credentials.credentials.length === 0) {
      section.append(element("p", { className: "muted", text: "No credential can authenticate as this application." }));
    }
    for (const credential of credentials.credentials) {
      const [status, statusClass] = credentialStatus(credential);
      const row = element("div", { className: "data-row" }, [
        element("div", {}, [
          element("div", { className: "data-row-title mono", text: credential.id }),
          element("div", { className: "data-row-meta", text: `Created ${formatDate(credential.created_at_unix_ms)}` }),
        ]),
        element("div", {}, [
          element("span", { className: `badge ${statusClass}`, text: status }),
          element("div", { className: "data-row-meta", text: `Last used: ${formatDate(credential.last_used_at_unix_ms)}` }),
        ]),
      ]);
      const revoke = element("button", { className: "button secondary", type: "button", text: "Revoke", disabled: credential.revoked_at_unix_ms !== null ? "" : null });
      revoke.addEventListener("click", async () => {
        const confirmed = await confirmAction(
          "Revoke this credential now?",
          "Requests using this credential will be denied immediately. This does not rotate any upstream secret the application may have read.",
          "Revoke credential",
        );
        if (!confirmed) return;
        try {
          await api.request(`/service-identities/${application.id}/credentials/${credential.id}/revoke`, {
            method: "POST",
            body: { expected_revision: credential.revision },
          });
          toast("Credential revoked. Requests using it will now be denied.");
          await renderApplicationDetail(application);
        } catch (error) {
          toast(formatError(error, "SMCV could not revoke this credential."));
        }
      });
      row.append(revoke);
      section.append(row);
    }
    page.lastElementChild.replaceWith(section);
  } catch (error) {
    page.lastElementChild.replaceWith(element("p", { className: "form-message error", role: "alert", text: formatError(error, "SMCV could not load credential metadata.") }));
  }
}

async function renderApplications() {
  clear(page);
  page.append(pageHeader("Workload identities", "Applications", "An identity has no authority until a policy is bound and no authentication until a credential is issued."), loadingState("Application identities"));
  try {
    const applications = await loadApplications();
    clear(page);
    page.append(pageHeader("Workload identities", "Applications", "An identity has no authority until a policy is bound and no authentication until a credential is issued.", [
      element("button", { className: "button primary", type: "button", text: "Create application", onclick: renderApplicationCreate }),
    ]));
    if (applications.length === 0) {
      page.append(element("section", { className: "empty-state" }, [
        element("h2", { text: "No application identities" }),
        element("p", { className: "muted", text: "Create one identity for one workload boundary, then grant only the exact actions and resources it needs." }),
        element("button", { className: "button primary", type: "button", text: "Create application", onclick: renderApplicationCreate }),
      ]));
      return;
    }
    const rows = element("div", { className: "data-list", "aria-label": "Application identities" });
    for (const application of applications) {
      rows.append(element("div", { className: "data-row" }, [
        element("div", {}, [
          element("div", { className: "data-row-title", text: application.label }),
          element("div", { className: "data-row-meta", text: application.description || "No description" }),
        ]),
        element("span", { className: `badge ${application.state === "active" ? "success" : "warning"}`, text: application.state }),
        element("button", { className: "button secondary", type: "button", text: "Open", onclick: () => renderApplicationDetail(application) }),
      ]));
    }
    page.append(rows);
  } catch (error) {
    clear(page);
    page.append(pageHeader("Workload identities", "Applications", "Application metadata could not be loaded."), element("p", { className: "form-message error", role: "alert", text: formatError(error, "SMCV could not load applications.") }));
  }
}

const grantActions = [
  ["namespace:list", "list namespace metadata"],
  ["secret:list", "list secrets"],
  ["secret:metadata-read", "read secret metadata"],
  ["secret:value-read", "reveal current secret values"],
  ["secret:create", "create secrets"],
  ["secret:update", "create new secret versions"],
  ["secret:archive", "archive secrets"],
  ["secret:restore", "restore archived secrets"],
  ["secret:history-read", "list immutable version history"],
  ["secret:version-read", "reveal historical secret values"],
];

function actionPhrase(action) {
  return grantActions.find(([value]) => value === action)?.[1] || action;
}

async function loadPolicies() {
  const policies = [];
  let after = null;
  do {
    const query = new URLSearchParams({ limit: "100" });
    if (after) query.set("after", after);
    const response = await api.request(`/policies?${query}`);
    policies.push(...response.policies);
    after = response.next_after;
  } while (after && policies.length < 1000);
  return policies;
}

async function renderPolicyCreate() {
  clear(page);
  const label = element("input", { id: "policy-label", required: "", maxlength: "128", autocomplete: "off" });
  const error = formError();
  const form = element("form", { className: "card stack" }, [
    formField("Policy label", label, "Name the workload purpose or access boundary, not a vague role such as general access."),
    element("div", { className: "callout" }, [
      element("strong", { text: "New policies allow nothing." }),
      element("p", { text: "Add exact grants and bind application identities only after reviewing the effective sentences." }),
    ]),
    error,
    element("div", { className: "page-actions" }, [
      element("button", { className: "button primary", type: "submit", text: "Create empty policy" }),
      element("button", { className: "button secondary", type: "button", text: "Cancel", onclick: renderAccess }),
    ]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = form.querySelector("button[type='submit']");
    submit.disabled = true;
    try {
      const created = await api.request("/policies", { method: "POST", body: { label: label.value } });
      toast("Empty policy created. It grants no access until rules and bindings are added.");
      await renderPolicyDetail({ id: created.id, label: label.value, state: "active", revision: 1 });
    } catch (requestError) {
      showFormError(error, requestError, "SMCV could not create this policy.");
      submit.disabled = false;
    }
  });
  page.append(pageHeader("Allow-only policy", "Create access policy", "Policies are additive. Deny rules and owner-only actions cannot be added."), form);
  label.focus();
}

async function loadActiveSecretsForPolicy(namespaces) {
  const records = [];
  for (const namespace of namespaces) {
    if (records.length >= 1000) break;
    const query = new URLSearchParams({ namespace_id: namespace.id, limit: "100" });
    try {
      const response = await api.request(`/secrets?${query}`);
      for (const secret of response.secrets) {
        records.push({ ...secret, namespace });
      }
    } catch (_error) {
      // A namespace may become unavailable between the tree and secret reads.
    }
  }
  return records;
}

async function renderGrantCreate(policy) {
  clear(page);
  page.append(pageHeader("Exact authority", `Add grant to ${policy.label}`, "Preview the action and target sentence before changing effective access."), loadingState("Available resources"));
  try {
    const namespaces = await loadNamespaceTree();
    const secrets = await loadActiveSecretsForPolicy(namespaces);
    const action = element("select", { id: "grant-action" }, grantActions.map(([value, label]) => element("option", { value, text: label })));
    const kind = element("select", { id: "grant-kind" }, [
      element("option", { value: "namespace", text: "Namespace" }),
      element("option", { value: "secret", text: "Exact secret" }),
    ]);
    const target = element("select", { id: "grant-target" });
    const descendants = element("input", { id: "grant-descendants", type: "checkbox" });
    const preview = element("p", { className: "callout", role: "status" });
    const error = formError();
    function updateTargets() {
      clear(target);
      const source = kind.value === "namespace" ? namespaces : secrets;
      for (const record of source) {
        target.append(element("option", {
          value: record.id,
          text: kind.value === "namespace" ? record.path.join(" / ") : `${record.namespace.path.join(" / ")} / ${record.metadata.name}`,
        }));
      }
      descendants.disabled = kind.value !== "namespace";
      if (descendants.disabled) descendants.checked = false;
      updatePreview();
    }
    function updatePreview() {
      const targetLabel = target.selectedOptions[0]?.textContent || "no available target";
      const scope = descendants.checked ? " and all descendant namespaces" : "";
      preview.textContent = `Applications bound to ${policy.label} can ${actionPhrase(action.value)} in ${targetLabel}${scope}.`;
    }
    for (const control of [action, kind, target, descendants]) control.addEventListener("change", kind === control ? updateTargets : updatePreview);
    updateTargets();
    const form = element("form", { className: "card stack" }, [
      formField("Action", action),
      formField("Resource type", kind),
      formField("Resource", target),
      element("label", { className: "checkbox-row", for: descendants.id }, [descendants, element("span", { text: "Include descendant namespaces" })]),
      preview,
      error,
      element("div", { className: "page-actions" }, [
        element("button", { className: "button primary", type: "submit", text: "Add this allow grant" }),
        element("button", { className: "button secondary", type: "button", text: "Cancel", onclick: () => renderPolicyDetail(policy) }),
      ]),
    ]);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = form.querySelector("button[type='submit']");
      submit.disabled = true;
      try {
        await api.request(`/policies/${policy.id}/grants`, {
          method: "POST",
          body: {
            action: action.value,
            resource_kind: kind.value,
            resource_id: target.value,
            include_descendants: descendants.checked,
          },
        });
        toast("Allow grant added. Bound applications receive it immediately.");
        await renderPolicyDetail(policy);
      } catch (requestError) {
        showFormError(error, requestError, "SMCV could not add this grant.");
        submit.disabled = false;
      }
    });
    clear(page);
    page.append(pageHeader("Exact authority", `Add grant to ${policy.label}`, "Preview the action and target sentence before changing effective access."), form);
  } catch (error) {
    clear(page);
    page.append(pageHeader("Exact authority", `Add grant to ${policy.label}`, "Available resources could not be loaded."), element("p", { className: "form-message error", role: "alert", text: formatError(error, "SMCV could not prepare this grant.") }));
  }
}

async function renderPolicyBinding(policy, applications) {
  clear(page);
  const service = element("select", { id: "policy-service" }, applications.map((application) => element("option", { value: application.id, text: application.label })));
  const preview = element("p", { className: "callout", text: applications.length > 0 ? `${service.selectedOptions[0].textContent} will receive every active grant in ${policy.label}.` : "No application identity is available to bind." });
  service.addEventListener("change", () => { preview.textContent = `${service.selectedOptions[0].textContent} will receive every active grant in ${policy.label}.`; });
  const error = formError();
  const submit = element("button", { className: "button primary", type: "submit", text: "Bind application", disabled: applications.length === 0 ? "" : null });
  const form = element("form", { className: "card stack" }, [
    formField("Application identity", service),
    preview,
    error,
    element("div", { className: "page-actions" }, [submit, element("button", { className: "button secondary", type: "button", text: "Cancel", onclick: () => renderPolicyDetail(policy) })]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    submit.disabled = true;
    try {
      await api.request(`/policies/${policy.id}/bindings`, { method: "POST", body: { service_principal_id: service.value } });
      toast("Policy bound. Effective application access changed immediately.");
      await renderPolicyDetail(policy);
    } catch (requestError) {
      showFormError(error, requestError, "SMCV could not bind this policy.");
      submit.disabled = false;
    }
  });
  page.append(pageHeader("Application authority", `Bind ${policy.label}`, "A binding applies every current and future grant in this policy to one workload identity."), form);
}

async function renderPolicyDetail(policy) {
  clear(page);
  page.append(pageHeader("Allow-only policy", policy.label, `Policy state: ${policy.state}. Revision ${policy.revision}.`), loadingState("Policy grants and bindings"));
  try {
    const [rules, applications, namespaces] = await Promise.all([
      api.request(`/policies/${policy.id}/rules`),
      loadApplications(),
      loadNamespaceTree(),
    ]);
    const namespaceNames = new Map(namespaces.map((namespace) => [namespace.id, namespace.path.join(" / ")]));
    const applicationNames = new Map(applications.map((application) => [application.id, application.label]));
    const archive = element("button", { className: "button secondary", type: "button", text: "Archive policy", disabled: policy.state !== "active" ? "" : null });
    archive.addEventListener("click", async () => {
      const confirmed = await confirmAction(
        "Archive this policy?",
        "Every application binding in this policy stops granting access on its next request. The policy record remains available for audit history.",
        "Archive policy",
      );
      if (!confirmed) return;
      try {
        const response = await api.request(`/policies/${policy.id}/archive`, { method: "POST", body: { expected_revision: policy.revision } });
        policy.state = "archived";
        policy.revision = response.revision;
        toast("Policy archived. Its grants no longer authorize application requests.");
        await renderPolicyDetail(policy);
      } catch (error) {
        toast(formatError(error, "SMCV could not archive this policy."));
      }
    });
    clear(page);
    page.append(pageHeader("Allow-only policy", policy.label, `Policy state: ${policy.state}. Authorization graph revision ${rules.authorization_revision}.`, [
      element("button", { className: "button secondary", type: "button", text: "Back to policies", onclick: renderAccess }),
      element("button", { className: "button secondary", type: "button", text: "Bind application", disabled: policy.state !== "active" ? "" : null, onclick: () => renderPolicyBinding(policy, applications) }),
      element("button", { className: "button primary", type: "button", text: "Add grant", disabled: policy.state !== "active" ? "" : null, onclick: () => renderGrantCreate(policy) }),
      archive,
    ]));
    const grants = element("section", { className: "card" }, [element("h2", { text: "Effective grant sentences" })]);
    if (rules.grants.length === 0) grants.append(element("p", { className: "muted", text: "This policy currently allows no actions." }));
    for (const grant of rules.grants) {
      const resource = grant.resource_kind === "namespace" ? (namespaceNames.get(grant.resource_id) || grant.resource_id) : grant.resource_id;
      grants.append(element("div", { className: "data-row" }, [
        element("div", { className: "data-row-title", text: `Bound applications can ${actionPhrase(grant.action)}.` }),
        element("div", { className: "data-row-meta", text: `${grant.resource_kind}: ${resource}${grant.include_descendants ? " and descendants" : ""}` }),
        element("span", { className: "badge success", text: "Allow" }),
      ]));
    }
    const bindings = element("section", { className: "card" }, [element("h2", { text: "Bound applications" })]);
    if (rules.bound_service_principal_ids.length === 0) bindings.append(element("p", { className: "muted", text: "No application receives these grants." }));
    for (const id of rules.bound_service_principal_ids) {
      bindings.append(element("div", { className: "data-row" }, [
        element("div", { className: "data-row-title", text: applicationNames.get(id) || "Application identity" }),
        element("div", { className: "data-row-meta mono", text: id }),
        element("span", { className: "badge success", text: "Bound" }),
      ]));
    }
    page.append(element("div", { className: "grid" }, [grants, bindings]));
  } catch (error) {
    page.lastElementChild.replaceWith(element("p", { className: "form-message error", role: "alert", text: formatError(error, "SMCV could not load this policy graph.") }));
  }
}

async function renderAccess() {
  clear(page);
  page.append(pageHeader("Effective authority", "Access policies", "Policies are allow-only. Owner administration actions never appear in application grants."), loadingState("Policies"));
  try {
    const policies = await loadPolicies();
    clear(page);
    page.append(pageHeader("Effective authority", "Access policies", "Policies are allow-only. Owner administration actions never appear in application grants.", [
      element("button", { className: "button primary", type: "button", text: "Create policy", onclick: renderPolicyCreate }),
    ]));
    if (policies.length === 0) {
      page.append(element("section", { className: "empty-state" }, [
        element("h2", { text: "No access policies" }),
        element("p", { className: "muted", text: "Applications have no vault authority until a policy with explicit grants is bound." }),
        element("button", { className: "button primary", type: "button", text: "Create empty policy", onclick: renderPolicyCreate }),
      ]));
      return;
    }
    const rows = element("div", { className: "data-list", "aria-label": "Access policies" });
    for (const policy of policies) {
      rows.append(element("div", { className: "data-row" }, [
        element("div", {}, [
          element("div", { className: "data-row-title", text: policy.label }),
          element("div", { className: "data-row-meta", text: `Revision ${policy.revision}` }),
        ]),
        element("span", { className: `badge ${policy.state === "active" ? "success" : "neutral"}`, text: policy.state }),
        element("button", { className: "button secondary", type: "button", text: "Review", onclick: () => renderPolicyDetail(policy) }),
      ]));
    }
    page.append(rows);
  } catch (error) {
    clear(page);
    page.append(pageHeader("Effective authority", "Access policies", "Policy metadata could not be loaded."), element("p", { className: "form-message error", role: "alert", text: formatError(error, "SMCV could not load access policies.") }));
  }
}

function auditSentence(event) {
  const actor = event.actor_principal_id ? `Principal ${event.actor_principal_id}` : "SMCV";
  const credential = event.credential_kind ? ` using ${event.credential_kind} credential ${event.credential_id || "unavailable"}` : "";
  const target = event.target_id ? `${event.target_kind} ${event.target_id}` : event.target_kind;
  return `${actor}${credential} attempted ${event.action} on ${target}: ${event.outcome}.`;
}

async function renderActivity() {
  clear(page);
  page.append(pageHeader("Security history", "Activity", "Events show safe actor, credential, action, target, decision, and absolute time. They never reconstruct secret values."), loadingState("Audit events"));
  try {
    const response = await api.request("/audit-events", { headers: { "X-SMCV-Page-Size": "250" } });
    clear(page);
    const filter = element("select", { id: "activity-filter" }, [
      element("option", { value: "all", text: "All outcomes" }),
      element("option", { value: "allowed", text: "Allowed" }),
      element("option", { value: "denied", text: "Denied" }),
      element("option", { value: "failed", text: "Failed" }),
    ]);
    const list = element("div", { className: "data-list", "aria-label": "Audit event timeline" });
    function renderEvents() {
      clear(list);
      const events = response.events.filter((event) => filter.value === "all" || event.outcome === filter.value);
      if (events.length === 0) {
        list.append(element("div", { className: "empty-state" }, [element("p", { text: "No events match this outcome filter." })]));
        return;
      }
      for (const event of events.slice().reverse()) {
        list.append(element("article", { className: "data-row" }, [
          element("div", {}, [
            element("div", { className: "data-row-title", text: auditSentence(event) }),
            element("div", { className: "data-row-meta", text: `Sequence ${event.sequence} · ${formatDate(event.occurred_at_unix_ms)}` }),
          ]),
          element("span", { className: `badge ${event.outcome === "allowed" ? "success" : event.outcome === "denied" ? "warning" : "danger"}`, text: event.outcome }),
          element("span", { className: "data-row-meta mono", text: `Request ${event.request_id}` }),
        ]));
      }
    }
    filter.addEventListener("change", renderEvents);
    page.append(
      pageHeader("Security history", "Activity", "Events show safe actor, credential, action, target, decision, and absolute time. They never reconstruct secret values."),
      element("section", { className: "card" }, [formField("Filter by outcome", filter)]),
      list,
    );
    renderEvents();
  } catch (error) {
    clear(page);
    page.append(pageHeader("Security history", "Activity", "Audit history could not be loaded."), element("p", { className: "form-message error", role: "alert", text: formatError(error, "SMCV could not load audit events.") }));
  }
}

function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return "Not available";
  const units = ["B", "KiB", "MiB", "GiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function backupState(job) {
  if (job.state === "completed") return ["Verified", "success"];
  if (job.state === "failed") return ["Failed", "danger"];
  return [job.state === "running" ? "Snapshot → encrypt → finalize → verify" : "Pending", "warning"];
}

function showBackupRecoveryKey(created) {
  clear(page);
  const raw = element("code", { className: "secret-value", "data-revealed-secret": "", tabindex: "0", "aria-label": "Display-once backup recovery key", text: created.recovery_key });
  const acknowledged = element("input", { id: "backup-key-acknowledged", type: "checkbox" });
  const continueButton = element("button", { className: "button primary", type: "button", text: "I stored the recovery key separately", disabled: "" });
  acknowledged.addEventListener("change", () => { continueButton.disabled = !acknowledged.checked; });
  continueButton.addEventListener("click", () => {
    raw.remove();
    renderBackups();
  });
  const copy = element("button", { className: "button secondary", type: "button", text: "Copy recovery key" });
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(created.recovery_key);
      toast("Copied to clipboard. Other applications or clipboard managers may retain it.");
    } catch (_error) {
      toast("SMCV could not copy the recovery key. Select it manually.");
    }
  });
  page.append(
    pageHeader("Display once", "Store the recovery key separately", "The encrypted archive cannot be restored without both its .smcvault file and this separate key."),
    element("section", { className: "card" }, [
      element("span", { className: "badge warning", text: "Recovery key revealed once" }),
      raw,
      copy,
      element("p", { className: "muted", text: `Backup job ${created.job_id}. The server artifact expires ${formatDate(created.expires_at_unix_ms)}.` }),
      element("label", { className: "checkbox-row", for: acknowledged.id }, [
        acknowledged,
        element("span", { text: "I stored this key somewhere separate from the .smcvault file." }),
      ]),
      continueButton,
    ]),
  );
  raw.focus();
}

async function renderBackupCreate() {
  clear(page);
  const mode = element("select", { id: "backup-key-mode" }, [
    element("option", { value: "generated_recovery", text: "Generated recovery key (recommended)" }),
    element("option", { value: "passphrase", text: "Passphrase" }),
  ]);
  const passphrase = element("input", { id: "backup-passphrase", type: "password", autocomplete: "new-password", minlength: "16", maxlength: "1024" });
  const confirmation = element("input", { id: "backup-passphrase-confirmation", type: "password", autocomplete: "new-password", minlength: "16", maxlength: "1024" });
  const passphraseFields = element("div", { className: "stack", hidden: "" }, [
    formField("Backup passphrase", passphrase, "Archive theft permits offline guesses. Use a unique password-manager-generated passphrase."),
    formField("Confirm passphrase", confirmation),
  ]);
  mode.addEventListener("change", () => {
    passphraseFields.hidden = mode.value !== "passphrase";
    passphrase.required = mode.value === "passphrase";
    confirmation.required = mode.value === "passphrase";
  });
  const custody = element("input", { id: "backup-custody-ready", type: "checkbox", required: "" });
  const error = formError();
  const submit = element("button", { className: "button primary", type: "submit", text: "Create and verify backup" });
  const form = element("form", { className: "card stack" }, [
    formField("Backup key mode", mode),
    passphraseFields,
    element("div", { className: "callout" }, [
      element("strong", { text: "Portable durable state is included." }),
      element("p", { text: "Secret history, policies, service identities, credential verifiers, and audit history are included. Sessions, source root keys, and raw credentials are excluded." }),
    ]),
    element("label", { className: "checkbox-row", for: custody.id }, [
      custody,
      element("span", { text: "I am ready to store the separate recovery material before downloading the archive." }),
    ]),
    error,
    element("div", { className: "page-actions" }, [submit, element("button", { className: "button secondary", type: "button", text: "Cancel", onclick: renderBackups })]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.hidden = true;
    if (!custody.checked) {
      error.textContent = "Confirm that you are ready to store the separate recovery material.";
      error.hidden = false;
      custody.focus();
      return;
    }
    if (mode.value === "passphrase" && (passphrase.value.length < 16 || passphrase.value !== confirmation.value)) {
      error.textContent = "The passphrase must contain at least 16 characters and both entries must match.";
      error.hidden = false;
      passphrase.focus();
      return;
    }
    submit.disabled = true;
    submit.textContent = "Starting verified backup…";
    const suppliedPassphrase = mode.value === "passphrase" ? passphrase.value : null;
    passphrase.value = "";
    confirmation.value = "";
    try {
      const created = await api.request("/backups", {
        method: "POST",
        body: { key_mode: mode.value, passphrase: suppliedPassphrase },
      });
      if (created.recovery_key) showBackupRecoveryKey(created);
      else {
        toast("Backup job started. Completion means the archive was reopened and verified.");
        await renderBackups();
      }
    } catch (requestError) {
      showFormError(error, requestError, "SMCV could not start this backup.");
      if (outcomeKnownNotCommitted(requestError)) {
        submit.disabled = false;
        submit.textContent = "Create and verify backup";
      } else {
        submit.textContent = "Reload backup status before retrying";
      }
    }
  });
  page.append(pageHeader("Portable recovery", "Create backup", "Created, verified, downloaded, and restore-tested are distinct states."), form);
  mode.focus();
}

function showBackupVerification(report) {
  clear(page);
  page.append(
    pageHeader("Non-mutating verification", "Backup verified and restore tested", "The uploaded archive completed authenticated integrity checks and a clean temporary staging restore. The current vault was not changed."),
    element("section", { className: "grid cards" }, [
      metricCard("Integrity", report.integrity_verified ? "Verified" : "Not verified", "Full archive", report.integrity_verified ? "success" : "danger"),
      metricCard("Restore drill", report.restore_tested ? "Passed" : "Not tested", "Clean staging", report.restore_tested ? "success" : "warning"),
      metricCard("Format", `Version ${report.format_version}`, `${report.record_count} records`, "neutral"),
      metricCard("Archive size", formatBytes(report.archive_bytes), formatBytes(report.logical_bytes) + " logical", "neutral"),
    ]),
    element("section", { className: "card stack" }, [
      element("h2", { text: "Authenticated archive metadata" }),
      element("p", { text: `Created ${formatDate(report.created_at_unix_ms)}` }),
      element("p", { className: "mono", text: `Archive ${report.archive_id}` }),
      element("p", { className: "mono", text: `Logical vault ${report.logical_vault_id}` }),
      element("p", { text: `Source recovery epoch ${report.source_recovery_epoch}; staging drill epoch ${report.staged_recovery_epoch}.` }),
      element("p", { className: "muted", text: "A restore drill demonstrates that this file and key can stage successfully here. It does not prove this is the newest backup, prove off-host custody, or activate a replacement installation." }),
      element("div", { className: "page-actions" }, [
        element("button", { className: "button primary", type: "button", text: "Verify another backup", onclick: renderBackupVerify }),
        element("button", { className: "button secondary", type: "button", text: "Back to backups", onclick: renderBackups }),
      ]),
    ]),
  );
}

async function renderBackupVerify() {
  clear(page);
  const archive = element("input", { id: "verify-archive", type: "file", accept: ".smcvault,application/octet-stream", required: "" });
  const mode = element("select", { id: "verify-key-mode" }, [
    element("option", { value: "generated_recovery", text: "Recovery key" }),
    element("option", { value: "passphrase", text: "Passphrase" }),
  ]);
  const key = element("input", { id: "verify-key", type: "password", autocomplete: "off", maxlength: "4096", required: "" });
  const error = formError();
  const submit = element("button", { className: "button primary", type: "submit", text: "Verify and restore test" });
  const form = element("form", { className: "card stack" }, [
    formField("Portable backup file", archive, "Select the encrypted .smcvault file. SMCV uploads it only to restrictive temporary storage for this check."),
    formField("Backup key type", mode),
    formField("Separate recovery key or passphrase", key, "The key is sent in a protected request field, used for this operation, and not retained."),
    element("div", { className: "callout warning" }, [
      element("strong", { text: "The current vault will not be changed." }),
      element("p", { text: "SMCV authenticates every archive frame, validates the logical contents, performs a clean temporary restore, and removes the temporary archive and staging vault afterward." }),
    ]),
    error,
    element("div", { className: "page-actions" }, [submit, element("button", { className: "button secondary", type: "button", text: "Cancel", onclick: renderBackups })]),
  ]);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.hidden = true;
    const selected = archive.files?.[0];
    if (!selected || !selected.name.toLowerCase().endsWith(".smcvault")) {
      error.textContent = "Select a .smcvault portable backup file.";
      error.hidden = false;
      archive.focus();
      return;
    }
    if (!key.value) {
      error.textContent = "Enter the separate recovery key or passphrase.";
      error.hidden = false;
      key.focus();
      return;
    }
    submit.disabled = true;
    submit.textContent = "Uploading and restore testing…";
    const data = new FormData();
    data.append("key_mode", mode.value);
    data.append("key", key.value);
    data.append("archive", selected, selected.name);
    key.value = "";
    try {
      const report = await api.upload("/backup-verifications", data);
      showBackupVerification(report);
    } catch (requestError) {
      showFormError(error, requestError, "Verification or the clean restore test failed. The current vault was not changed. Check the file and separate key, then try again.");
      submit.disabled = false;
      submit.textContent = "Verify and restore test";
      key.focus();
    }
  });
  page.append(pageHeader("Portable recovery", "Verify an existing backup", "A header check is not enough; this workflow performs full integrity validation and a clean restore exercise."), form);
  archive.focus();
}

async function renderBackups() {
  clear(page);
  page.append(pageHeader("Portable recovery", "Backup and recovery", "A server artifact is temporary and does not prove off-host custody."), loadingState("Backup jobs"));
  try {
    const response = await api.request("/backups");
    clear(page);
    page.append(
      pageHeader("Portable recovery", "Backup and recovery", "A server artifact is temporary and does not prove off-host custody.", [
        element("button", { className: "button primary", type: "button", text: "Create backup", onclick: renderBackupCreate }),
        element("button", { className: "button secondary", type: "button", text: "Verify existing backup", onclick: renderBackupVerify }),
      ]),
      element("section", { className: "callout warning" }, [
        element("strong", { text: "Keep two separate items." }),
        element("p", { text: "Retain the downloaded .smcvault file off-host and retain its passphrase or recovery key separately. Losing the only copy of either makes restoration impossible." }),
      ]),
      element("section", { className: "card stack" }, [
        element("h2", { text: "Restore after host loss" }),
        element("p", { text: "On the empty destination host, start a short-lived browser ceremony from a local terminal. This avoids exposing any remotely claimable restore endpoint on the normal server." }),
        element("code", { className: "mono", text: "smcv backup-restore-browser --database /new/data/vault.sqlite --root-key /separate/provider/root.key" }),
        element("p", { className: "muted", text: "The CLI binds only to loopback, displays a one-use URL, authenticates archive metadata before activation, offers preserve-or-revoke credential handling, and closes after one activation attempt or ten minutes." }),
      ]),
    );
    if (response.backups.length === 0) {
      page.append(element("section", { className: "empty-state" }, [
        element("h2", { text: "No unexpired server artifacts" }),
        element("p", { className: "muted", text: "Create a portable archive, store its separate key, download it, and later complete an isolated restore test." }),
        element("button", { className: "button primary", type: "button", text: "Create backup", onclick: renderBackupCreate }),
      ]));
      return;
    }
    const rows = element("div", { className: "data-list", "aria-label": "Temporary backup artifacts" });
    for (const job of response.backups) {
      const [status, statusClass] = backupState(job);
      const actions = element("div", { className: "page-actions" });
      if (job.state === "completed") {
        actions.append(element("a", {
          className: "button primary",
          href: `/api/v1/backups/${job.job_id}/download`,
          download: `${job.job_id}.smcvault`,
          text: job.downloaded ? "Download again" : "Download archive",
        }));
      }
      const remove = element("button", { className: "button secondary", type: "button", text: "Delete server artifact", disabled: ["pending", "running"].includes(job.state) ? "" : null });
      remove.addEventListener("click", async () => {
        const confirmed = await confirmAction(
          "Delete this server artifact?",
          "This removes the temporary encrypted archive and its safe job status from this server. It does not affect an off-host file you already downloaded.",
          "Delete server artifact",
          "Warning",
        );
        if (!confirmed) return;
        try {
          await api.request(`/backups/${job.job_id}`, { method: "DELETE" });
          toast("Temporary server artifact deleted.");
          await renderBackups();
        } catch (error) {
          toast(formatError(error, "SMCV could not delete this artifact."));
        }
      });
      actions.append(remove);
      rows.append(element("article", { className: "data-row" }, [
        element("div", {}, [
          element("div", { className: "data-row-title mono", text: job.archive_id || job.job_id }),
          element("div", { className: "data-row-meta", text: `Created ${formatDate(job.created_at_unix_ms)} · expires ${formatDate(job.expires_at_unix_ms)}` }),
          element("div", { className: "data-row-meta", text: `${formatBytes(job.archive_bytes)} · ${job.record_count ?? "unknown"} logical records · format ${job.format_version ?? "pending"} · ${job.downloaded ? "downloaded" : "not downloaded"}` }),
          element("div", { className: "data-row-meta mono", text: job.logical_vault_id ? `Logical vault ${job.logical_vault_id} · recovery epoch ${job.source_recovery_epoch}` : "Logical vault metadata pending verification" }),
        ]),
        element("span", { className: `badge ${statusClass}`, text: status }),
        actions,
      ]));
    }
    page.append(rows);
    if (response.backups.some((job) => ["pending", "running"].includes(job.state))) {
      window.setTimeout(() => {
        if (!appView.hidden && routeFromHash() === "backups") renderBackups();
      }, 1500);
    }
  } catch (error) {
    clear(page);
    page.append(pageHeader("Portable recovery", "Backup and recovery", "Backup status could not be loaded."), element("p", { className: "form-message error", role: "alert", text: formatError(error, "SMCV could not load backup jobs.") }));
  }
}

async function registerPasskey(button, message) {
  if (!window.PublicKeyCredential) {
    message.textContent = "This browser cannot register a passkey. Password authentication remains available.";
    message.hidden = false;
    return;
  }
  button.disabled = true;
  button.textContent = "Waiting for passkey…";
  message.hidden = true;
  try {
    const challenge = await api.request("/session/passkeys/registration/options", { method: "POST" });
    const credential = await navigator.credentials.create({ publicKey: publicKeyCreation(challenge.options) });
    if (!credential) throw new Error("Passkey response was not available.");
    await api.request("/session/passkeys/registration/verify", {
      method: "POST",
      body: { ceremony_id: challenge.ceremony_id, response: registrationResponse(credential) },
    });
    message.textContent = "Passkey registered. Keep the owner password available as a recovery-compatible fallback.";
    message.className = "form-message";
    message.hidden = false;
  } catch (error) {
    message.textContent = formatError(error, "SMCV could not register this passkey.");
    message.className = "form-message error";
    message.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Register a passkey";
  }
}

async function renderSettings() {
  clear(page);
  page.append(pageHeader("Local installation", "Settings", "Installation-bound settings and authentication methods do not travel automatically with a restored host."), loadingState("Session state"));
  try {
    const session = await api.session();
    clear(page);
    const passkeyMessage = element("p", { className: "form-message", role: "status", hidden: "" });
    const register = element("button", { className: "button secondary", type: "button", text: "Register a passkey" });
    register.addEventListener("click", () => registerPasskey(register, passkeyMessage));
    page.append(
      pageHeader("Local installation", "Settings", "Installation-bound settings and authentication methods do not travel automatically with a restored host."),
      element("div", { className: "grid cards" }, [
        element("section", { className: "card" }, [
          element("div", { className: "card-header" }, [
            element("h2", { text: "Current session" }),
            element("span", { className: `badge ${session.recent ? "success" : "warning"}`, text: session.recent ? "Recently authenticated" : "Recent authentication expired" }),
          ]),
          element("p", { className: "muted", text: "High-risk changes require recent authentication. Locking invalidates this server-side session." }),
          element("button", { className: "button secondary", type: "button", text: "Lock this session", onclick: () => document.querySelector("#logout").click() }),
        ]),
        element("section", { className: "card" }, [
          element("div", { className: "card-header" }, [element("h2", { text: "Passkey" }), element("span", { className: "badge neutral", text: "Source-bound" })]),
          element("p", { className: "muted", text: "Passkeys are bound to this configured relying-party identity. A restore may require reenrollment on the destination." }),
          register,
          passkeyMessage,
        ]),
        element("section", { className: "card" }, [
          element("div", { className: "card-header" }, [element("h2", { text: "Encryption state" }), element("span", { className: "badge success", text: "Encrypted at rest" })]),
          element("p", { className: "muted", text: "The running unlocked process can decrypt values after authorization. Encryption at rest does not protect against control of this unlocked host." }),
        ]),
      ]),
    );
  } catch (error) {
    showLogin(formatError(error, "SMCV could not validate this browser session."));
  }
}

async function renderOverview() {
  clear(page);
  page.append(pageHeader("Current state", "Overview", "Actionable vault, access, and recovery state. Counts do not imply that every item has been reviewed."), loadingState("Recovery status"));
  let backups = [];
  try {
    const response = await api.request("/backups");
    backups = response.backups;
  } catch (_error) {
    // The overview remains useful while the dedicated backup page reports details.
  }
  const verified = backups.filter((job) => job.state === "completed");
  const downloaded = verified.some((job) => job.downloaded);
  clear(page);
  page.append(
    pageHeader("Current state", "Overview", "Actionable vault, access, and recovery state. Counts do not imply that every item has been reviewed."),
    element("div", { className: "grid cards" }, [
      metricCard("Vault process", "Unlocked", "Ready", "success"),
      metricCard("Verified backups", String(verified.length), verified.length > 0 ? "Created and verified" : "None", verified.length > 0 ? "success" : "warning"),
      metricCard("Backup custody", downloaded ? "Download observed" : "Not confirmed here", "Off-host copy unproven", "warning"),
      metricCard("Restore drill", "No browser record", "Not tested", "neutral"),
    ]),
    element("section", { className: "card" }, [
      element("h2", { text: "Start with recovery" }),
      element("p", { className: "muted", text: "A portable backup requires both the .smcvault file and its separate passphrase or recovery key. A server download is not an off-host retained copy." }),
      element("a", { className: "button secondary", href: "#backups", text: "Review backup and recovery" }),
    ]),
  );
}

function renderPlaceholder(route) {
  const labels = {
    secrets: ["Protected records", "Secrets", "Secret metadata is shown without fetching plaintext values."],
    applications: ["Workload identities", "Applications", "Create narrowly scoped identities and rotate their display-once credentials."],
    access: ["Effective authority", "Access policies", "Review actor, action, resource, and inherited namespace scope before granting access."],
    activity: ["Security history", "Activity", "Audit events distinguish identity, credential, action, target, decision, and absolute time."],
    backups: ["Portable recovery", "Backup and recovery", "Created, verified, downloaded, and restore-tested are separate states."],
    settings: ["Local installation", "Settings", "Review installation-bound behavior, passkeys, key maintenance, and session state."],
  };
  const [eyebrow, title, description] = labels[route];
  clear(page);
  page.append(
    pageHeader(eyebrow, title, description),
    element("section", { className: "empty-state" }, [
      element("span", { className: "badge neutral", text: "Loading next slice" }),
      element("h2", { text: `${title} workspace` }),
      element("p", { className: "muted", text: "The authenticated shell is ready. This workflow is being connected to its existing bounded API." }),
    ]),
  );
}

function routeFromHash() {
  const candidate = window.location.hash.replace(/^#/, "") || "overview";
  return routes.has(candidate) ? candidate : "overview";
}

async function renderRoute() {
  const route = routeFromHash();
  for (const link of document.querySelectorAll("[data-route]")) {
    if (link.dataset.route === route) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  if (route === "overview") await renderOverview();
  else if (route === "secrets") await renderSecrets();
  else if (route === "applications") await renderApplications();
  else if (route === "access") await renderAccess();
  else if (route === "activity") await renderActivity();
  else if (route === "backups") await renderBackups();
  else if (route === "settings") await renderSettings();
  else renderPlaceholder(route);
  sidebar.classList.remove("open");
  navToggle.setAttribute("aria-expanded", "false");
  main.focus({ preventScroll: true });
  announce(`${route} page loaded`);
}

function showLogin(message = null) {
  api.clearCsrf();
  appView.hidden = true;
  loginView.hidden = false;
  skipLink.href = "#login-title";
  skipLink.textContent = "Skip to authentication";
  clear(page);
  if (message) {
    loginError.textContent = message;
    loginError.hidden = false;
  }
  passwordInput.value = "";
  passwordInput.focus();
}

function showApp() {
  loginError.hidden = true;
  loginError.textContent = "";
  loginView.hidden = true;
  appView.hidden = false;
  skipLink.href = "#main-content";
  skipLink.textContent = "Skip to main content";
  if (!window.location.hash) window.location.hash = "overview";
  renderRoute();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  loginError.hidden = true;
  const submit = loginForm.querySelector("button[type='submit']");
  submit.disabled = true;
  submit.textContent = "Authenticating…";
  try {
    const session = await api.login(passwordInput.value);
    api.setCsrf(session.csrf_token);
    passwordInput.value = "";
    showApp();
  } catch (error) {
    passwordInput.value = "";
    loginError.textContent = formatError(error, "SMCV could not authenticate this session.");
    loginError.hidden = false;
    passwordInput.focus();
  } finally {
    submit.disabled = false;
    submit.textContent = "Continue with password";
  }
});

document.querySelector("#passkey-login").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  loginError.hidden = true;
  if (!window.PublicKeyCredential) {
    loginError.textContent = "This browser cannot use passkeys here. Continue with the owner password.";
    loginError.hidden = false;
    return;
  }
  button.disabled = true;
  button.textContent = "Waiting for passkey…";
  try {
    const challenge = await api.request("/session/passkeys/authentication/options", { method: "POST" });
    const credential = await navigator.credentials.get({ publicKey: publicKeyRequest(challenge.options) });
    if (!credential) throw new Error("Passkey response was not available.");
    const session = await api.request("/session/passkeys/authentication/verify", {
      method: "POST",
      body: { ceremony_id: challenge.ceremony_id, response: authenticationResponse(credential) },
    });
    api.setCsrf(session.csrf_token);
    showApp();
  } catch (error) {
    loginError.textContent = formatError(error, "SMCV could not authenticate this passkey.");
    loginError.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Continue with a passkey";
  }
});

document.querySelector("#logout").addEventListener("click", async () => {
  try {
    await api.logout();
    showLogin("The local and server-side session are locked. Authenticate again to continue.");
  } catch (_error) {
    showLogin("Local sensitive content was removed, but SMCV could not confirm server-side session revocation. Close this browser and retry locking when the service is available.");
  }
});

navToggle.addEventListener("click", () => {
  const open = !sidebar.classList.contains("open");
  sidebar.classList.toggle("open", open);
  navToggle.setAttribute("aria-expanded", String(open));
});

window.addEventListener("hashchange", () => {
  if (!appView.hidden) renderRoute();
});

window.addEventListener("smcv:authentication-required", () => {
  if (!appView.hidden) showLogin("Authenticate again to continue. The previous request did not commit a change.");
});

document.addEventListener("visibilitychange", () => {
  if (document.hidden && document.querySelector("[data-revealed-secret]")) {
    clear(page);
    page.append(element("section", { className: "callout warning" }, [
      element("h1", { text: "Sensitive value hidden" }),
      element("p", { text: "SMCV removed the revealed value when this page lost visibility." }),
    ]));
    sensitiveViewCleared = true;
  } else if (!document.hidden && sensitiveViewCleared && !appView.hidden) {
    sensitiveViewCleared = false;
    renderRoute();
  }
});

async function initialize() {
  try {
    await api.session();
    await api.logout();
    showLogin("The page was reloaded, so SMCV revoked the previous server-side session. Authenticate again to continue.");
  } catch (_error) {
    showLogin();
  }
}

initialize();
