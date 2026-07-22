#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, open, readFile, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const repository = path.resolve(import.meta.dirname, "..");
const evidenceDirectory = path.join(repository, "ai_phase_evidence", "phase_4_browser");
const syntheticPassword = "synthetic browser owner password";
const syntheticSecret = "synthetic-browser-secret-value";
const screenReaderMode = process.env.SMCV_SCREEN_READER === "1";
const serverEnvironment = { ...process.env };
delete serverEnvironment.SMCV_SCREEN_READER;
const temporary = await mkdtemp(path.join(os.tmpdir(), "smcv-browser-"));
const children = [];
let sessionId = null;
let orcaProcess = null;

function child(command, args, options = {}) {
  const process = spawn(command, args, { cwd: repository, ...options });
  children.push(process);
  return process;
}

function completed(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const process = child(command, args, { stdio: ["ignore", "pipe", "pipe"], ...options });
    let output = "";
    let errors = "";
    process.stdout?.on("data", (chunk) => { output += chunk; });
    process.stderr?.on("data", (chunk) => { errors += chunk; });
    process.on("exit", (code) => code === 0 ? resolve(output) : reject(new Error(`${command} failed (${code}): ${errors}`)));
  });
}

async function availablePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  const address = server.address();
  await new Promise((resolve) => server.close(resolve));
  return address.port;
}

async function waitFor(url, attempts = 100) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch (_error) {
      // The local process may still be starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`timed out waiting for ${url}`);
}

async function webdriver(method, endpoint, body) {
  const response = await fetch(`http://127.0.0.1:${driverPort}${endpoint}`, {
    method,
    signal: AbortSignal.timeout(15_000),
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok || result.value?.error) throw new Error(`WebDriver ${method} ${endpoint}: ${JSON.stringify(result.value)}`);
  return result.value;
}

async function execute(script, args = []) {
  return webdriver("POST", `/session/${sessionId}/execute/sync`, { script, args });
}

async function find(selector) {
  const value = await webdriver("POST", `/session/${sessionId}/element`, { using: "css selector", value: selector });
  return value["element-6066-11e4-a52e-4f735466cecf"];
}

async function click(selector) {
  const element = await find(selector);
  await webdriver("POST", `/session/${sessionId}/element/${element}/click`, {});
}

async function type(selector, text) {
  const element = await find(selector);
  await webdriver("POST", `/session/${sessionId}/element/${element}/value`, { text });
}

async function accessibility(selector) {
  const element = await find(selector);
  const [role, name] = await Promise.all([
    webdriver("GET", `/session/${sessionId}/element/${element}/computedrole`),
    webdriver("GET", `/session/${sessionId}/element/${element}/computedlabel`),
  ]);
  return { role, name };
}

async function waitText(text, attempts = 100) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const present = await execute("return document.body.textContent.includes(arguments[0]);", [text]);
    if (present) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`rendered page did not contain: ${text}`);
}

async function screenshot(name) {
  const encoded = await webdriver("GET", `/session/${sessionId}/screenshot`);
  await writeFile(path.join(evidenceDirectory, name), Buffer.from(encoded, "base64"));
}

const serverPort = await availablePort();
const driverPort = await availablePort();
const dataDirectory = path.join(temporary, "data");
const keyDirectory = path.join(temporary, "provider");
const database = path.join(dataDirectory, "vault.sqlite");
const rootKey = path.join(keyDirectory, "root.key");

try {
  if (!screenReaderMode) await rm(evidenceDirectory, { recursive: true, force: true });
  await mkdir(evidenceDirectory, { recursive: true });
  await completed("cargo", ["build", "--workspace"]);
  await completed(path.join(repository, "target/debug/smcv-cli"), ["init", "--database", database, "--root-key", rootKey]);
  const passwordFile = path.join(temporary, "synthetic-password-input");
  await writeFile(passwordFile, `${syntheticPassword}\n`, { mode: 0o600 });
  const passwordHandle = await open(passwordFile, "r");
  await new Promise((resolve, reject) => {
    const process = child(path.join(repository, "target/debug/smcv-cli"), ["enroll-owner", "--database", database, "--root-key", rootKey, "--password-fd", "3"], { stdio: ["ignore", "pipe", "pipe", passwordHandle.fd] });
    process.on("exit", (code) => code === 0 ? resolve() : reject(new Error(`owner enrollment failed (${code})`)));
  });
  await passwordHandle.close();
  await rm(passwordFile, { force: true });

  child(path.join(repository, "target/debug/smcv-server"), [], {
    env: {
      ...serverEnvironment,
      SMCV_LISTEN_ADDR: `127.0.0.1:${serverPort}`,
      SMCV_DATA_DIR: dataDirectory,
      SMCV_KEY_DIR: keyDirectory,
      SMCV_RP_ID: "localhost",
      SMCV_ORIGIN: `http://localhost:${serverPort}`,
      RUST_LOG: "warn",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`http://127.0.0.1:${serverPort}/health/live`);
  await completed("chromium-browser", [
    "--headless", "--no-sandbox", "--disable-gpu", "--force-high-contrast",
    "--window-size=320,900",
    `--screenshot=${path.join(evidenceDirectory, "00-login-forced-colors.png")}`,
    `http://localhost:${serverPort}/`,
  ]);
  await completed("chromium-browser", [
    "--headless", "--no-sandbox", "--disable-gpu", "--force-device-scale-factor=2",
    "--window-size=320,900",
    `--screenshot=${path.join(evidenceDirectory, "06-login-2x-scale-320csspx.png")}`,
    `http://localhost:${serverPort}/`,
  ]);
  child("geckodriver", ["--port", String(driverPort)], { stdio: ["ignore", "pipe", "pipe"] });
  await waitFor(`http://127.0.0.1:${driverPort}/status`);
  const orcaDebug = path.join(temporary, "orca-debug.log");
  if (screenReaderMode) {
    await mkdir(path.join(temporary, "orca-preferences"));
    orcaProcess = child("orca", ["--replace", "--user-prefs", path.join(temporary, "orca-preferences"), "--debug", "--debug-file", orcaDebug, "--disable", "speech"], { stdio: ["ignore", "pipe", "pipe"] });
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  const session = await webdriver("POST", "/session", {
    capabilities: { alwaysMatch: { browserName: "firefox", "moz:firefoxOptions": { args: screenReaderMode ? [] : ["-headless"], prefs: { "ui.prefersReducedMotion": 1 } } } },
  });
  sessionId = session.sessionId;
  await webdriver("POST", `/session/${sessionId}/window/rect`, { width: 500, height: 900 });
  await webdriver("POST", `/session/${sessionId}/url`, { url: `http://localhost:${serverPort}/` });
  await waitText("Unlock your control surface");
  const loginAccessibility = {
    skip: await accessibility("#skip-link"),
    password: await accessibility("#password"),
    submit: await accessibility("#login-form button[type='submit']"),
  };
  const skipLinkText = await execute("return document.querySelector('#skip-link').textContent.trim();");
  await screenshot("01-login-narrow.png");
  await type("#password", syntheticPassword);
  await click("#login-form button[type='submit']");
  await waitText("Start with recovery");
  await screenshot("02-overview-narrow.png");

  await click("#nav-toggle");
  await click("a[data-route='secrets']");
  await waitText("Create the first namespace");
  await click("#page button.primary");
  await waitText("Namespace details");
  await type("#namespace-name", "Synthetic production");
  await type("#namespace-description", "Browser acceptance fixture");
  await click("#page form button[type='submit']");
  await waitText("No active secrets in this namespace");
  await click("#page .page-header button.primary");
  await waitText("Secret details");
  await type("#secret-name", "Synthetic database credential");
  await type("#secret-username", "synthetic-service");
  await type("#secret-description", "Non-production browser fixture");
  await type("#secret-value", syntheticSecret);
  await click("#page form button[type='submit']");
  await waitText("Current immutable version 1");
  const absentBeforeReveal = !(await execute("return document.body.textContent.includes(arguments[0]);", [syntheticSecret]));
  await screenshot("03-secret-hidden-narrow.png");
  await click("#page .secret-mask + button.primary");
  await waitText(syntheticSecret);
  const presentAfterReveal = await execute("return document.body.textContent.includes(arguments[0]);", [syntheticSecret]);
  await click("#page [data-revealed-secret] + .page-actions button:first-child");
  const absentAfterHide = !(await execute("return document.body.textContent.includes(arguments[0]);", [syntheticSecret]));

  await click("#nav-toggle");
  await click("a[data-route='backups']");
  await waitText("Restore after host loss");
  const backupAccessibility = {
    heading: await accessibility("#page h1"),
    create: await accessibility("#page .page-header button.primary"),
    verify: await accessibility("#page .page-header button.secondary"),
  };
  await execute("document.querySelector('#main-content').focus(); return true;");
  await webdriver("POST", `/session/${sessionId}/actions`, {
    actions: [{ type: "key", id: "keyboard", actions: [{ type: "keyDown", value: "\uE004" }, { type: "keyUp", value: "\uE004" }] }],
  });
  const keyboardTarget = await execute("return document.activeElement.textContent.trim();");
  const absentAfterNavigation = !(await execute("return document.body.textContent.includes(arguments[0]);", [syntheticSecret]));
  await screenshot("04-backup-recovery-narrow.png");
  const narrow = await execute(`
    const visible = (node) => node.getClientRects().length > 0;
    const unlabeledControls = [...document.querySelectorAll("input, select, textarea")].filter((node) => visible(node) && !node.labels?.length && !node.getAttribute("aria-label")).length;
    const unnamedButtons = [...document.querySelectorAll("button")].filter((node) => visible(node) && !node.textContent.trim() && !node.getAttribute("aria-label")).length;
    const sidebarMotion = getComputedStyle(document.querySelector("#primary-navigation")).transitionDuration;
    return {innerWidth, scrollWidth: document.documentElement.scrollWidth, localStorage: localStorage.length, sessionStorage: sessionStorage.length, unlabeledControls, unnamedButtons, h1Count: [...document.querySelectorAll("h1")].filter(visible).length, reducedMotion: matchMedia("(prefers-reduced-motion: reduce)").matches, sidebarMotion};
  `);
  await webdriver("POST", `/session/${sessionId}/window/rect`, { width: 1280, height: 900 });
  await execute("window.scrollTo(0, 0); return true;");
  await screenshot("05-backup-recovery-wide.png");
  const wide = await execute("return {innerWidth, scrollWidth: document.documentElement.scrollWidth};");
  await webdriver("DELETE", `/session/${sessionId}`);
  sessionId = null;
  const zoomSession = await webdriver("POST", "/session", {
    capabilities: { alwaysMatch: { browserName: "firefox", "moz:firefoxOptions": { args: screenReaderMode ? [] : ["-headless"], prefs: { "layout.css.devPixelsPerPx": "2.0", "ui.prefersReducedMotion": 1 } } } },
  });
  sessionId = zoomSession.sessionId;
  await webdriver("POST", `/session/${sessionId}/window/rect`, { width: 640, height: 900 });
  await webdriver("POST", `/session/${sessionId}/url`, { url: `http://localhost:${serverPort}/` });
  await waitText("Unlock your control surface");
  const zoomed = await execute("return {devicePixelRatio, innerWidth, scrollWidth: document.documentElement.scrollWidth};");
  await screenshot("07-login-firefox-2x-scale.png");
  let screenReader = null;
  if (screenReaderMode) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    const debug = await readFile(orcaDebug, "utf8");
    screenReader = {
      debugProduced: debug.length > 0,
      activeDuringBrowserExercise: orcaProcess?.exitCode === null,
      debugExposedAccessibleNames: false,
      ownerPasswordNamed: debug.toLowerCase().includes("owner password"),
      passwordActionNamed: debug.toLowerCase().includes("continue with password"),
      backupHeadingNamed: debug.toLowerCase().includes("backup and recovery"),
    };
    screenReader.debugExposedAccessibleNames = screenReader.ownerPasswordNamed
      && screenReader.passwordActionNamed
      && screenReader.backupHeadingNamed;
  }
  const results = {
    date: new Date().toISOString(),
    browser: session.capabilities.browserVersion,
    platform: session.capabilities.platformName,
    checks: {
      absentBeforeReveal,
      presentAfterReveal,
      absentAfterHide,
      absentAfterNavigation,
      browserStorageEmpty: narrow.localStorage === 0 && narrow.sessionStorage === 0,
      visibleControlsNamed: narrow.unlabeledControls === 0 && narrow.unnamedButtons === 0,
      skipLinkNamed: skipLinkText === "Skip to authentication",
      oneVisiblePageHeading: narrow.h1Count === 1,
      accessibilityTreeNames: loginAccessibility.password.name === "Owner password"
        && loginAccessibility.submit.name === "Continue with password"
        && backupAccessibility.heading.name === "Backup and recovery"
        && backupAccessibility.create.name === "Create backup"
        && backupAccessibility.verify.name === "Verify existing backup",
      reflowNarrow: narrow.scrollWidth <= narrow.innerWidth,
      reflowWide: wide.scrollWidth <= wide.innerWidth,
      reducedMotionApplied: narrow.reducedMotion && parseFloat(narrow.sidebarMotion) <= 0.001,
      keyboardEntersPageActions: keyboardTarget === "Create backup",
      twoXScaleNoOverflow: zoomed.devicePixelRatio >= 1.9 && zoomed.scrollWidth <= zoomed.innerWidth,
      ...(screenReaderMode ? { orcaExercisedWithFirefox: screenReader.debugProduced && screenReader.activeDuringBrowserExercise } : {}),
    },
    accessibility: { login: loginAccessibility, backups: backupAccessibility },
    layout: { narrow, wide, zoomed },
    screenReader,
  };
  if (Object.values(results.checks).some((value) => !value)) throw new Error(`browser checks failed: ${JSON.stringify(results)}`);
  const evidenceName = screenReaderMode ? "screen-reader-smoke.json" : "browser-smoke.json";
  await writeFile(path.join(evidenceDirectory, evidenceName), `${JSON.stringify(results, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
} finally {
  if (sessionId !== null) {
    try { await webdriver("DELETE", `/session/${sessionId}`); } catch (_error) { /* best effort */ }
  }
  for (const process of children.reverse()) {
    if (process.exitCode === null) {
      try { process.kill("SIGTERM"); } catch (_error) { /* Snap-managed browser helpers may reject direct signals. */ }
    }
    process.stdout?.destroy();
    process.stderr?.destroy();
    process.unref();
  }
  await rm(temporary, { recursive: true, force: true });
}
