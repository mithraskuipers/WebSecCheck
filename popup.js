function badge(level, text) {
  return `<span class="badge ${level}">${text}</span>`;
}
function row(level, name, detail) {
  return `<div class="row">${badge(level, level.toUpperCase())}<div class="name">${name}</div><div class="detail">${detail}</div></div>`;
}

// ---------- Header checks ----------
function checkHeaders(headers, isHttps) {
  const out = [];
  const h = headers || {};

  if (!isHttps) {
    out.push(row("info", "HSTS", "Page not loaded over HTTPS, skipped."));
  } else if (!h["strict-transport-security"]) {
    out.push(row("fail", "HSTS", "Missing. Allows SSL-stripping / protocol downgrade attacks."));
  } else {
    const m = h["strict-transport-security"].match(/max-age=(\d+)/i);
    const maxAge = m ? parseInt(m[1], 10) : 0;
    if (maxAge < 15768000) {
      out.push(row("warn", "HSTS", `Present but max-age is low (${maxAge}s). Recommend >= 15768000 (6 months).`));
    } else {
      out.push(row("pass", "HSTS", h["strict-transport-security"]));
    }
  }

  const csp = h["content-security-policy"];
  if (!csp) {
    out.push(row("fail", "CSP", "Missing. No mitigation against XSS/injection."));
  } else if (/unsafe-inline|unsafe-eval/i.test(csp)) {
    out.push(row("warn", "CSP", "Present but allows 'unsafe-inline' or 'unsafe-eval'."));
  } else {
    out.push(row("pass", "CSP", "Present, no unsafe-inline/unsafe-eval found."));
  }

  const xfo = h["x-frame-options"];
  const hasFrameAncestors = csp && /frame-ancestors/i.test(csp);
  if (!xfo && !hasFrameAncestors) {
    out.push(row("fail", "Clickjacking", "No X-Frame-Options and no frame-ancestors in CSP."));
  } else {
    out.push(row("pass", "Clickjacking", xfo ? `X-Frame-Options: ${xfo}` : "CSP frame-ancestors set."));
  }

  if ((h["x-content-type-options"] || "").toLowerCase() !== "nosniff") {
    out.push(row("fail", "X-Content-Type-Options", "Missing or not 'nosniff'. MIME-sniffing possible."));
  } else {
    out.push(row("pass", "X-Content-Type-Options", "nosniff"));
  }

  const rp = (h["referrer-policy"] || "").toLowerCase();
  if (!rp) {
    out.push(row("warn", "Referrer-Policy", "Missing. Full referrer may leak to third parties."));
  } else if (rp.includes("unsafe-url")) {
    out.push(row("warn", "Referrer-Policy", "Set to 'unsafe-url', leaks full URL cross-origin."));
  } else {
    out.push(row("pass", "Referrer-Policy", rp));
  }

  if (!h["permissions-policy"]) {
    out.push(row("info", "Permissions-Policy", "Missing. Optional but restricts browser feature access."));
  } else {
    out.push(row("pass", "Permissions-Policy", "Present."));
  }

  out.push(row(h["cross-origin-opener-policy"] ? "pass" : "info", "COOP",
    h["cross-origin-opener-policy"] || "Missing (relevant for cross-origin isolation)."));
  out.push(row(h["cross-origin-embedder-policy"] ? "pass" : "info", "COEP",
    h["cross-origin-embedder-policy"] || "Missing (relevant for cross-origin isolation)."));

  // CORS sanity on the main document response
  const acao = h["access-control-allow-origin"];
  const acac = (h["access-control-allow-credentials"] || "").toLowerCase();
  if (acao === "*" && acac === "true") {
    out.push(row("fail", "CORS", "Access-Control-Allow-Origin: * combined with Allow-Credentials: true. Invalid/dangerous combo if it ever applies to authenticated responses."));
  } else if (acao) {
    out.push(row(acao === "*" ? "info" : "pass", "CORS", `Access-Control-Allow-Origin: ${acao}`));
  }

  if (h["server"]) out.push(row("warn", "Server header", `Reveals: ${h["server"]}`));
  if (h["x-powered-by"]) out.push(row("warn", "X-Powered-By", `Reveals: ${h["x-powered-by"]}`));

  return out.join("");
}

// ---------- Cookie checks ----------
function checkCookies(cookies, isHttps) {
  if (!cookies || cookies.length === 0) {
    return `<div class="empty">No cookies found for this origin.</div>`;
  }
  return cookies.map((c) => {
    const issues = [];
    let level = "pass";
    if (isHttps && !c.secure) { issues.push("missing Secure flag"); level = "fail"; }
    if (!c.httpOnly) { issues.push("missing HttpOnly"); if (level !== "fail") level = "warn"; }
    const sameSite = (c.sameSite || "unspecified").toLowerCase();
    if (sameSite === "no_restriction" || sameSite === "unspecified") {
      issues.push(`SameSite=${sameSite}`);
      if (level !== "fail") level = "warn";
    }
    const detail = issues.length ? issues.join(", ") : `Secure, HttpOnly, SameSite=${sameSite}`;
    return row(level, c.name, detail);
  }).join("");
}

// ---------- Page-level DOM checks (runs inside the page) ----------
function collectPageSignals() {
  const result = {
    mixedContent: [],
    insecureForms: [],
    passwordIssues: [],
    inlineScriptCount: 0,
    inlineHandlerCount: 0,
    missingSRI: [],
    sensitiveStorageKeys: { local: [], session: [] },
    possibleSecrets: [],
    thirdPartyDomains: [],
    openRedirectParams: []
  };
  const isHttps = location.protocol === "https:";
  const selfHost = location.host;

  // Mixed content
  if (isHttps) {
    document.querySelectorAll("img[src], script[src], link[href], iframe[src], source[src]").forEach((el) => {
      const url = el.src || el.href;
      if (url && url.startsWith("http://")) result.mixedContent.push(url);
    });
  }

  // Forms
  document.querySelectorAll("form").forEach((f) => {
    const action = f.getAttribute("action") || "(same page)";
    const method = (f.getAttribute("method") || "get").toLowerCase();
    if (isHttps && /^http:\/\//i.test(action)) {
      result.insecureForms.push({ action, method });
    }
    const pw = f.querySelector('input[type="password"]');
    if (pw) {
      if (!isHttps) result.passwordIssues.push("Password field on a page served over plain HTTP.");
      if (method === "get") result.passwordIssues.push(`Password field in a form using method="get" (action: ${action}).`);
    }
  });

  // Inline scripts / handlers (rough CSP-relevance signal)
  result.inlineScriptCount = document.querySelectorAll("script:not([src])").length;
  let handlerCount = 0;
  document.querySelectorAll("*").forEach((el) => {
    for (const attr of el.attributes || []) {
      if (attr.name.startsWith("on")) handlerCount++;
    }
  });
  result.inlineHandlerCount = handlerCount;

  // Subresource Integrity on cross-origin script/style
  document.querySelectorAll("script[src], link[rel=stylesheet][href]").forEach((el) => {
    const url = el.src || el.href;
    if (!url) return;
    try {
      const u = new URL(url, location.href);
      if (u.host !== selfHost && !el.getAttribute("integrity")) {
        result.missingSRI.push(url);
      }
    } catch (e) {}
  });

  // Third-party domains contacted via static resources
  const domains = new Set();
  document.querySelectorAll("script[src], img[src], iframe[src], link[href]").forEach((el) => {
    const url = el.src || el.href;
    if (!url) return;
    try {
      const u = new URL(url, location.href);
      if (u.host && u.host !== selfHost) domains.add(u.host);
    } catch (e) {}
  });
  result.thirdPartyDomains = Array.from(domains).slice(0, 25);

  // Sensitive-looking keys in Web Storage
  const sensitivePattern = /(token|jwt|secret|password|passwd|apikey|api_key|session|auth)/i;
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (sensitivePattern.test(k)) result.sensitiveStorageKeys.local.push(k);
    }
  } catch (e) {}
  try {
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      if (sensitivePattern.test(k)) result.sensitiveStorageKeys.session.push(k);
    }
  } catch (e) {}

  // Lightweight secret-pattern scan of the rendered HTML (first 300k chars)
  const html = document.documentElement.outerHTML.slice(0, 300000);
  const patterns = [
    { name: "AWS Access Key", re: /AKIA[0-9A-Z]{16}/g },
    { name: "Private key block", re: /-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/g },
    { name: "Generic secret assignment", re: /(secret|apikey|api_key|access_token)["']?\s*[:=]\s*["'][0-9a-zA-Z\-_]{16,45}["']/gi }
  ];
  patterns.forEach((p) => {
    const matches = html.match(p.re);
    if (matches) result.possibleSecrets.push({ name: p.name, count: matches.length });
  });

  // Open-redirect-style query params
  const redirectParamNames = ["redirect", "redirect_uri", "return", "return_url", "returnurl", "next", "url", "dest", "destination", "continue"];
  const params = new URLSearchParams(location.search);
  redirectParamNames.forEach((p) => {
    if (params.has(p)) result.openRedirectParams.push(`${p}=${params.get(p)}`);
  });

  return result;
}

function renderPageChecks(sig, isHttps) {
  const out = [];

  if (isHttps) {
    out.push(sig.mixedContent.length
      ? row("fail", "Mixed content", `${sig.mixedContent.length} resource(s) loaded over HTTP: ${sig.mixedContent.slice(0, 3).join(", ")}${sig.mixedContent.length > 3 ? "…" : ""}`)
      : row("pass", "Mixed content", "None detected."));
  }

  out.push(sig.insecureForms.length
    ? row("fail", "Form actions", `${sig.insecureForms.length} form(s) submit to plain HTTP: ${sig.insecureForms.map(f => f.action).slice(0,3).join(", ")}`)
    : row("pass", "Form actions", "No forms submitting to HTTP found."));

  if (sig.passwordIssues.length) {
    sig.passwordIssues.forEach(msg => out.push(row("fail", "Password field", msg)));
  } else {
    out.push(row("pass", "Password field", "No issues detected on visible forms."));
  }

  out.push(row("info", "Inline scripts", `${sig.inlineScriptCount} inline <script> block(s), ${sig.inlineHandlerCount} inline event handler attribute(s). Relevant if you plan to tighten CSP to remove 'unsafe-inline'.`));

  out.push(sig.missingSRI.length
    ? row("warn", "Subresource Integrity", `${sig.missingSRI.length} cross-origin script/style tag(s) without an integrity attribute: ${sig.missingSRI.slice(0,3).join(", ")}${sig.missingSRI.length > 3 ? "…" : ""}`)
    : row("pass", "Subresource Integrity", "Cross-origin scripts/styles all carry an integrity attribute (or none are cross-origin)."));

  const sensKeys = [...sig.sensitiveStorageKeys.local.map(k => `local:${k}`), ...sig.sensitiveStorageKeys.session.map(k => `session:${k}`)];
  out.push(sensKeys.length
    ? row("warn", "Web Storage", `Sensitive-looking key(s) in localStorage/sessionStorage: ${sensKeys.join(", ")}. These are readable by any script (XSS-accessible).`)
    : row("pass", "Web Storage", "No obviously sensitive-named keys found."));

  out.push(sig.possibleSecrets.length
    ? row("warn", "Secrets in HTML", sig.possibleSecrets.map(p => `${p.name} (${p.count}x)`).join(", "))
    : row("pass", "Secrets in HTML", "No obvious secret patterns found in rendered HTML (best-effort, not exhaustive)."));

  out.push(row("info", "Third-party hosts", sig.thirdPartyDomains.length
    ? `${sig.thirdPartyDomains.length} distinct external host(s) loaded: ${sig.thirdPartyDomains.slice(0,6).join(", ")}${sig.thirdPartyDomains.length > 6 ? "…" : ""}`
    : "None detected."));

  out.push(sig.openRedirectParams.length
    ? row("warn", "Redirect-style params", `URL contains parameter(s) worth testing for open redirect: ${sig.openRedirectParams.join(", ")}`)
    : row("info", "Redirect-style params", "None found in current URL."));

  return out.join("");
}

// ---------- Recon (robots.txt / security.txt) ----------
async function runRecon(origin) {
  const out = [];
  async function tryFetch(path, label) {
    try {
      const res = await fetch(origin + path, { credentials: "omit" });
      if (res.ok) {
        const text = (await res.text()).slice(0, 2000);
        const lineCount = text.split("\n").filter(l => l.trim()).length;
        out.push(row("info", label, `Found (HTTP ${res.status}), ${lineCount} non-empty line(s).`));
      } else {
        out.push(row("info", label, `Not found (HTTP ${res.status}).`));
      }
    } catch (e) {
      out.push(row("info", label, `Could not fetch (${e.message}).`));
    }
  }
  await tryFetch("/robots.txt", "robots.txt");
  await tryFetch("/.well-known/security.txt", "security.txt");
  return out.join("");
}

// ---------- Main flow ----------
let lastResults = null;

async function runOne(tab) {
  const isHttps = tab.url.startsWith("https:");
  const record = await chrome.runtime.sendMessage({ type: "GET_HEADERS", tabId: tab.id });
  const cookies = await chrome.cookies.getAll({ url: tab.url });

  let pageSignals = null;
  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: collectPageSignals
    });
    pageSignals = result;
  } catch (e) {
    // e.g. chrome:// pages or restricted origins
  }

  return { url: tab.url, isHttps, record, cookies, pageSignals };
}

async function run() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url || !/^https?:/.test(tab.url)) {
    document.getElementById("url").textContent = "Unsupported page (not http/https).";
    return;
  }
  document.getElementById("url").textContent = tab.url;
  document.getElementById("status").textContent = "Scanning…";

  const data = await runOne(tab);
  lastResults = data;

  document.getElementById("headers").innerHTML = data.record
    ? checkHeaders(data.record.headers, data.isHttps)
    : `<div class="empty">No captured response yet. Reload the page, then click Re-scan.</div>`;

  document.getElementById("cookies").innerHTML = checkCookies(data.cookies, data.isHttps);

  document.getElementById("page").innerHTML = data.pageSignals
    ? renderPageChecks(data.pageSignals, data.isHttps)
    : `<div class="empty">Could not run page-level checks on this tab (restricted page).</div>`;

  const origin = new URL(tab.url).origin;
  document.getElementById("recon").innerHTML = `<div class="empty">Fetching…</div>`;
  document.getElementById("recon").innerHTML = await runRecon(origin);

  document.getElementById("status").textContent = "";
}

async function scanAllTabs() {
  document.getElementById("status").textContent = "Scanning all tabs…";
  const tabs = await chrome.tabs.query({});
  const results = [];
  for (const tab of tabs) {
    if (!tab.url || !/^https?:/.test(tab.url)) continue;
    const data = await runOne(tab);
    results.push(data);
  }
  lastResults = { multiTab: true, tabs: results };
  downloadJSON(lastResults, "websec-auditor-all-tabs.json");
  document.getElementById("status").textContent = `Scanned ${results.length} tab(s), exported JSON.`;
}

function downloadJSON(obj, filename) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

document.getElementById("refresh").addEventListener("click", run);
document.getElementById("export").addEventListener("click", () => {
  if (lastResults) downloadJSON(lastResults, "websec-auditor-report.json");
});
document.getElementById("scanAll").addEventListener("click", scanAllTabs);

run();
