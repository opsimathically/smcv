const API_ROOT = "/api/v1";

export class ApiFailure extends Error {
  constructor(status, body) {
    super(body?.message || "SMCV could not complete the request.");
    this.name = "ApiFailure";
    this.status = status;
    this.code = body?.code || "request_failed";
    this.requestId = body?.request_id || null;
  }
}

export class ApiClient {
  #csrf = null;

  setCsrf(value) {
    this.#csrf = value;
  }

  clearCsrf() {
    this.#csrf = null;
  }

  async request(path, options = {}) {
    const method = options.method || "GET";
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    if (options.body !== undefined) {
      headers.set("Content-Type", "application/json");
    }
    if (!/^(GET|HEAD|OPTIONS)$/.test(method) && this.#csrf) {
      headers.set("X-SMCV-CSRF", this.#csrf);
    }
    const response = await fetch(`${API_ROOT}${path}`, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: options.signal,
    });
    if (!response.ok) {
      let body = null;
      try {
        body = await response.json();
      } catch (_error) {
        body = null;
      }
      if (response.status === 401 && path !== "/session/password") {
        window.dispatchEvent(new Event("smcv:authentication-required"));
      }
      throw new ApiFailure(response.status, body);
    }
    if (response.status === 204) return null;
    return response.json();
  }

  async upload(path, formData, options = {}) {
    const headers = new Headers({ Accept: "application/json" });
    if (this.#csrf) headers.set("X-SMCV-CSRF", this.#csrf);
    const response = await fetch(`${API_ROOT}${path}`, {
      method: "POST",
      headers,
      body: formData,
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: options.signal,
    });
    if (!response.ok) {
      let body = null;
      try {
        body = await response.json();
      } catch (_error) {
        body = null;
      }
      if (response.status === 401) window.dispatchEvent(new Event("smcv:authentication-required"));
      throw new ApiFailure(response.status, body);
    }
    return response.json();
  }

  login(password) {
    return this.request("/session/password", { method: "POST", body: { password } });
  }

  session() {
    return this.request("/session");
  }

  logout() {
    return this.request("/session", {
      method: "DELETE",
      headers: { "X-SMCV-Session-Lock": "1" },
    });
  }
}
