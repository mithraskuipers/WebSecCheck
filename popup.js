// ---------- Finding rendering ----------
// Each check produces: { level: pass|warn|fail|info, title, observed, why, recommendation }
// "why" and "recommendation" are only shown (and only required) for warn/fail.

function renderItem(f) {
  const badgeClass = `${f.level}-badge`;
  const expandFinding = (f.level === "fail" || f.level === "warn") && (f.why || f.recommendation);
  const hasValue = f.value !== undefined;
  let body = "";
  if (expandFinding || hasValue) {
    body = `<div class="item-body">
      ${hasValue ? `<div class="finding-label">Raw value (${f.valueLength} chars)</div><div class="finding-text cookie-value">${escapeHtml(f.value)}</div>` : ""}
      ${f.why ? `<div class="finding-label">Why this is a finding</div><div class="finding-text">${f.why}</div>` : ""}
      ${f.recommendation ? `<div class="finding-label">Recommended remediation</div><div class="finding-text">${f.recommendation}</div>` : ""}
    </div>`;
  }
  return `<div class="item">
    <div class="item-head"><span class="badge ${badgeClass}">${f.level.toUpperCase()}</span><span class="item-title">${f.title}</span></div>
    <div class="item-observed">${f.observed}</div>
    ${body}
  </div>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function renderSection(findings) {
  if (!findings || findings.length === 0) return `<div class="empty">No checks ran.</div>`;
  return findings.map(renderItem).join("");
}

function renderSummary(allFindings) {
  const counts = { pass: 0, warn: 0, fail: 0, info: 0 };
  allFindings.forEach(f => { counts[f.level] = (counts[f.level] || 0) + 1; });
  const box = (cls, label, n) => `<div class="sum-${cls}"><span class="sum-count">${n}</span><span class="sum-label">${label}</span></div>`;
  return box("fail", "FAIL", counts.fail) + box("warn", "WARN", counts.warn) + box("pass", "PASS", counts.pass) + box("info", "INFO", counts.info);
}

// ---------- Header checks ----------
function checkHeaders(headers, isHttps) {
  const h = headers || {};
  const out = [];

  if (!isHttps) {
    out.push({ level: "info", title: "HSTS", observed: "Page not loaded over HTTPS, check skipped." });
  } else if (!h["strict-transport-security"]) {
    out.push({
      level: "fail", title: "Missing Strict-Transport-Security (HSTS)",
      observed: "No Strict-Transport-Security header on the response.",
      why: "Without HSTS, a user's browser will still attempt plain-HTTP connections to this host (e.g. from a typed URL, a bookmark, or an attacker-controlled link). An on-path attacker can intercept that first HTTP request and strip TLS (SSL-stripping), proxying the session and reading/modifying traffic even though the site 'supports' HTTPS.",
      recommendation: "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` on all HTTPS responses, and consider HSTS preload list submission for the apex domain."
    });
  } else {
    const m = h["strict-transport-security"].match(/max-age=(\d+)/i);
    const maxAge = m ? parseInt(m[1], 10) : 0;
    if (maxAge < 15768000) {
      out.push({
        level: "warn", title: "Weak HSTS max-age",
        observed: `Strict-Transport-Security: ${h["strict-transport-security"]}`,
        why: `A max-age of ${maxAge} seconds is short. Once it expires, the browser reverts to allowing plain-HTTP for this host, re-opening the SSL-stripping window described above, until the site is visited again over HTTPS.`,
        recommendation: "Increase max-age to at least 15768000 (6 months), ideally 31536000 (1 year) with includeSubDomains."
      });
    } else {
      out.push({ level: "pass", title: "HSTS present and adequately configured", observed: h["strict-transport-security"] });
    }
  }

  const csp = h["content-security-policy"];
  if (!csp) {
    out.push({
      level: "fail", title: "Missing Content-Security-Policy",
      observed: "No Content-Security-Policy header on the response.",
      why: "CSP is the primary browser-side control against script injection (reflected/stored/DOM XSS). Without it, any successful HTML/JS injection executes with full page privileges, no defense-in-depth is in place.",
      recommendation: "Deploy a restrictive CSP (start with `default-src 'self'`, add specific sources as needed, avoid `unsafe-inline`/`unsafe-eval`). Roll out in Report-Only mode first if the app is complex."
    });
  } else if (/unsafe-inline|unsafe-eval/i.test(csp)) {
    out.push({
      level: "warn", title: "CSP allows unsafe-inline / unsafe-eval",
      observed: csp,
      why: "`unsafe-inline` and `unsafe-eval` disable CSP's main protection against XSS: they let injected `<script>` tags or `eval()`-style code run just as if no CSP were present at all.",
      recommendation: "Migrate inline scripts to external files or use nonces/hashes (`script-src 'nonce-...'`), and remove `unsafe-eval` by avoiding `eval`/`new Function`/string-based `setTimeout`."
    });
  } else {
    out.push({ level: "pass", title: "CSP present without unsafe-inline/unsafe-eval", observed: csp });
  }

  const xfo = h["x-frame-options"];
  const hasFrameAncestors = csp && /frame-ancestors/i.test(csp);
  if (!xfo && !hasFrameAncestors) {
    out.push({
      level: "fail", title: "No clickjacking protection",
      observed: "Neither X-Frame-Options nor a CSP frame-ancestors directive is set.",
      why: "The page can be embedded in an <iframe> on an attacker-controlled site and overlaid with deceptive UI, tricking users into clicking real page elements (clickjacking) — relevant for any state-changing action reachable while authenticated.",
      recommendation: "Add `Content-Security-Policy: frame-ancestors 'self'` (preferred) or `X-Frame-Options: DENY`/`SAMEORIGIN` if framing is never required."
    });
  } else {
    out.push({ level: "pass", title: "Clickjacking protection present", observed: xfo ? `X-Frame-Options: ${xfo}` : "CSP frame-ancestors directive set." });
  }

  if ((h["x-content-type-options"] || "").toLowerCase() !== "nosniff") {
    out.push({
      level: "fail", title: "Missing X-Content-Type-Options",
      observed: "Header missing or not set to 'nosniff'.",
      why: "Without `nosniff`, some browsers will MIME-sniff response bodies and may render a response as HTML/JS even when the server declared a different content type (e.g. a user-uploaded 'image' that's actually HTML), enabling stored XSS via file upload endpoints.",
      recommendation: "Add `X-Content-Type-Options: nosniff` on all responses, and ensure upload endpoints serve user content from a separate, script-disabled origin."
    });
  } else {
    out.push({ level: "pass", title: "X-Content-Type-Options: nosniff present", observed: "nosniff" });
  }

  const rp = (h["referrer-policy"] || "").toLowerCase();
  if (!rp) {
    out.push({
      level: "warn", title: "Missing Referrer-Policy",
      observed: "No Referrer-Policy header set.",
      why: "Browser default behaviour can send the full request URL (including query-string tokens, session identifiers, or other sensitive parameters) to third-party origins referenced by outbound links or embedded resources.",
      recommendation: "Set `Referrer-Policy: strict-origin-when-cross-origin` (or stricter, e.g. `no-referrer`, for pages carrying sensitive URL parameters)."
    });
  } else if (rp.includes("unsafe-url")) {
    out.push({
      level: "warn", title: "Referrer-Policy set to unsafe-url",
      observed: `Referrer-Policy: ${rp}`,
      why: "`unsafe-url` always forwards the full URL, including path and query string, to any destination the browser navigates to or fetches from, including plain-HTTP and third-party destinations.",
      recommendation: "Use `strict-origin-when-cross-origin` or `no-referrer` instead."
    });
  } else {
    out.push({ level: "pass", title: "Referrer-Policy configured safely", observed: rp });
  }

  if (!h["permissions-policy"]) {
    out.push({ level: "info", title: "Permissions-Policy not set", observed: "Missing. Optional hardening header restricting browser feature access (camera, geolocation, etc.) for this page and any iframes it embeds." });
  } else {
    out.push({ level: "pass", title: "Permissions-Policy present", observed: h["permissions-policy"] });
  }

  out.push({
    level: h["cross-origin-opener-policy"] ? "pass" : "info",
    title: "Cross-Origin-Opener-Policy",
    observed: h["cross-origin-opener-policy"] || "Missing. Optional; enables process isolation from cross-origin popups (mitigates some Spectre-class and window.opener attacks)."
  });
  out.push({
    level: h["cross-origin-embedder-policy"] ? "pass" : "info",
    title: "Cross-Origin-Embedder-Policy",
    observed: h["cross-origin-embedder-policy"] || "Missing. Optional; required alongside COOP for full cross-origin isolation."
  });

  const acao = h["access-control-allow-origin"];
  const acac = (h["access-control-allow-credentials"] || "").toLowerCase();
  if (acao === "*" && acac === "true") {
    out.push({
      level: "fail", title: "Dangerous CORS configuration",
      observed: "Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.",
      why: "This combination is invalid per the Fetch spec and browsers ignore the credentials flag when the origin is '*' — but seeing it configured this way on a live response usually signals a reverse-proxy or app-level bug where the intent was to reflect the requesting Origin. If any code path actually reflects an arbitrary Origin with credentials allowed, any website can read authenticated API responses on behalf of a logged-in victim.",
      recommendation: "Never combine a wildcard origin with credentialed CORS. Reflect a specific, validated allow-list of origins instead, and confirm credentialed endpoints never fall back to '*'."
    });
  } else if (acao) {
    out.push({
      level: acao === "*" ? "info" : "pass",
      title: "CORS header present",
      observed: `Access-Control-Allow-Origin: ${acao}${acao === "*" ? " (fine for public, non-credentialed responses only)" : ""}`
    });
  }

  if (h["server"]) {
    out.push({
      level: "warn", title: "Server header discloses software/version",
      observed: `Server: ${h["server"]}`,
      why: "Publicly disclosing server software and version narrows an attacker's reconnaissance effort, letting them target known CVEs for that exact version instead of fingerprinting it themselves.",
      recommendation: "Suppress or generalise the Server header at the web server/reverse-proxy/CDN layer."
    });
  }
  if (h["x-powered-by"]) {
    out.push({
      level: "warn", title: "X-Powered-By discloses backend framework",
      observed: `X-Powered-By: ${h["x-powered-by"]}`,
      why: "Same rationale as the Server header: framework/version disclosure aids targeted exploitation.",
      recommendation: "Disable the X-Powered-By header (e.g. `app.disable('x-powered-by')` in Express, or equivalent for the framework in use)."
    });
  }

  return out;
}

// ---------- Cookie checks ----------
const SESSION_LIKE_RE = /(sess|sid|jsessionid|phpsessid|auth|token|jwt|login|account|uid|identity)/i;

// Plain list of cookie names present for this origin, with basic scope/lifetime info
// and the raw value (for manual replay/tampering testing). This is informational
// (not pass/fail) so it always renders even when everything else is safe.
// NOTE: raw values are live session material — anything you export or screenshot
// from this section should be handled like credentials.
function buildCookieInventory(cookies) {
  if (!cookies || cookies.length === 0) return [];
  return cookies.map((c) => ({
    level: "info",
    title: `Cookie: ${c.name}`,
    observed: `Domain: ${c.domain}${c.hostOnly ? " (host-only)" : " (domain-wide — sent to all subdomains)"} | Path: ${c.path} | ${c.session ? "Session cookie (deleted on browser close)" : `Persistent, expires ${new Date(c.expirationDate * 1000).toLocaleDateString()}`}${SESSION_LIKE_RE.test(c.name) ? " | Looks like a session/auth cookie" : ""}`,
    value: c.value,
    valueLength: c.value ? c.value.length : 0
  }));
}

// Per-cookie hijacking-focused risk assessment: for each of the three ways a cookie
// can be stolen or ridden (network sniffing, XSS/JS access, cross-site request), state
// plainly whether this cookie is protected against it.
function checkCookies(cookies, isHttps) {
  if (!cookies || cookies.length === 0) {
    return [{ level: "info", title: "Cookies", observed: "No cookies found for this origin." }];
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
    const isSessionLike = SESSION_LIKE_RE.test(c.name);
    const domainWide = c.hostOnly === false;
    if (isSessionLike && domainWide) {
      issues.push("scoped to entire parent domain, not just this host");
      if (level === "pass") level = "warn";
    }

    if (level === "pass") {
      return {
        level: "pass", title: `Cookie: ${c.name} — resistant to common hijacking vectors`,
        observed: `Secure, HttpOnly, SameSite=${sameSite}${isSessionLike ? ", host-scoped" : ""}. Network sniffing (needs Secure bypass), JS/XSS theft (needs HttpOnly bypass), and cross-site riding (needs SameSite bypass) are all mitigated for this cookie.`
      };
    }

    const whyParts = [];
    const recParts = [];
    if (issues.some(i => i.includes("Secure"))) {
      whyParts.push("Hijacking via network interception: without the Secure flag, the browser will also send this cookie over a plain-HTTP connection to the same host, so anyone on the network path (open Wi-Fi, a malicious proxy, ARP spoofing on a LAN) can capture it and replay it to impersonate the user — no XSS needed.");
      recParts.push("Set the Secure attribute on this cookie.");
    }
    if (issues.some(i => i.includes("HttpOnly"))) {
      whyParts.push("Hijacking via XSS: without HttpOnly, `document.cookie` can read this cookie from JavaScript. Any injected script (stored, reflected, or DOM XSS anywhere on the site) can exfiltrate it to an attacker-controlled server, who then simply sets the same cookie in their own browser to take over the session — this is the classic 'cookie hijacking' path.");
      recParts.push("Set the HttpOnly attribute so the cookie is inaccessible to JavaScript.");
    }
    if (issues.some(i => i.includes("SameSite"))) {
      whyParts.push("Hijacking-adjacent risk via cross-site requests: a weak/unset SameSite value means this cookie still rides along on requests triggered from another site the victim has open, which is the precondition for CSRF and can be chained with other bugs to act as the victim without ever stealing the cookie value itself.");
      recParts.push("Set SameSite=Lax (or Strict where the flow allows) unless this cookie specifically needs cross-site delivery, in which case pair SameSite=None with Secure and add CSRF tokens.");
    }
    if (issues.some(i => i.includes("parent domain"))) {
      whyParts.push("Broadened attack surface: this looks like a session/auth cookie but is scoped to the whole parent domain rather than just this host, so it is also sent to (and can potentially be set by) every subdomain. A vulnerability on any single subdomain — an XSS bug, a forgotten dev host, a subdomain takeover — can be used to steal or overwrite this cookie for the whole domain.");
      recParts.push("Scope session/auth cookies to the specific host that needs them rather than the parent domain, unless true cross-subdomain SSO is a requirement.");
    }
    return {
      level, title: `Cookie: ${c.name}${isSessionLike ? " (session/auth-like)" : ""}`,
      observed: issues.join(", "),
      why: whyParts.join(" "),
      recommendation: recParts.join(" ")
    };
  });
}

// ---------- Page-level DOM checks (runs inside the page) ----------
function collectPageSignals() {
  const result = {
    mixedContent: [], insecureForms: [], passwordIssues: [], inlineScriptCount: 0,
    inlineHandlerCount: 0, missingSRI: [], sensitiveStorageKeys: { local: [], session: [] },
    possibleSecrets: [], thirdPartyDomains: [], openRedirectParams: []
  };
  const isHttps = location.protocol === "https:";
  const selfHost = location.host;

  if (isHttps) {
    document.querySelectorAll("img[src], script[src], link[href], iframe[src], source[src]").forEach((el) => {
      const url = el.src || el.href;
      if (url && url.startsWith("http://")) result.mixedContent.push(url);
    });
  }

  document.querySelectorAll("form").forEach((f) => {
    const action = f.getAttribute("action") || "(same page)";
    const method = (f.getAttribute("method") || "get").toLowerCase();
    if (isHttps && /^http:\/\//i.test(action)) result.insecureForms.push({ action, method });
    const pw = f.querySelector('input[type="password"]');
    if (pw) {
      if (!isHttps) result.passwordIssues.push("Password field on a page served over plain HTTP.");
      if (method === "get") result.passwordIssues.push(`Password field in a form using method="get" (action: ${action}).`);
    }
  });

  result.inlineScriptCount = document.querySelectorAll("script:not([src])").length;
  let handlerCount = 0;
  document.querySelectorAll("*").forEach((el) => {
    for (const attr of el.attributes || []) if (attr.name.startsWith("on")) handlerCount++;
  });
  result.inlineHandlerCount = handlerCount;

  document.querySelectorAll("script[src], link[rel=stylesheet][href]").forEach((el) => {
    const url = el.src || el.href;
    if (!url) return;
    try {
      const u = new URL(url, location.href);
      if (u.host !== selfHost && !el.getAttribute("integrity")) result.missingSRI.push(url);
    } catch (e) {}
  });

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

  const redirectParamNames = ["redirect", "redirect_uri", "return", "return_url", "returnurl", "next", "url", "dest", "destination", "continue"];
  const params = new URLSearchParams(location.search);
  redirectParamNames.forEach((p) => { if (params.has(p)) result.openRedirectParams.push(`${p}=${params.get(p)}`); });

  return result;
}

function pageChecksToFindings(sig, isHttps) {
  const out = [];

  if (isHttps) {
    out.push(sig.mixedContent.length ? {
      level: "fail", title: "Mixed content",
      observed: `${sig.mixedContent.length} resource(s) loaded over HTTP: ${sig.mixedContent.slice(0,3).join(", ")}${sig.mixedContent.length > 3 ? "…" : ""}`,
      why: "Resources fetched over plain HTTP on an HTTPS page can be intercepted or tampered with by an on-path attacker (e.g. malicious/altered JavaScript), undermining the transport security the padlock implies, and modern browsers may block or warn on it.",
      recommendation: "Serve every subresource over HTTPS; update hard-coded http:// references or use protocol-relative/absolute HTTPS URLs."
    } : { level: "pass", title: "Mixed content", observed: "None detected." });
  }

  out.push(sig.insecureForms.length ? {
    level: "fail", title: "Form submits to plain HTTP",
    observed: `${sig.insecureForms.length} form(s): ${sig.insecureForms.map(f => f.action).slice(0,3).join(", ")}`,
    why: "Data entered into this form (which may include credentials or other sensitive input) is transmitted unencrypted, making it readable and modifiable by anyone on the network path.",
    recommendation: "Change the form action to an https:// URL, or remove the explicit http:// action so it inherits the page's HTTPS origin."
  } : { level: "pass", title: "Form actions", observed: "No forms submitting to HTTP found." });

  if (sig.passwordIssues.length) {
    sig.passwordIssues.forEach(msg => out.push({
      level: "fail", title: "Password field handling issue", observed: msg,
      why: msg.includes("plain HTTP")
        ? "Credentials submitted from an HTTP-served page can be captured in transit even if the form posts to HTTPS, because the page itself (and any script on it) was not delivered securely and could be tampered with beforehand."
        : "GET requests place form values, including the password, into the URL. URLs are commonly logged by browsers (history), web servers (access logs), proxies, and can be leaked via the Referer header — persisting the password in plaintext in multiple places.",
      recommendation: msg.includes("plain HTTP")
        ? "Serve any page containing a login/password form over HTTPS end-to-end."
        : "Change the form method to POST for any request carrying a password."
    }));
  } else {
    out.push({ level: "pass", title: "Password field handling", observed: "No issues detected on visible forms." });
  }

  out.push({ level: "info", title: "Inline scripts / handlers", observed: `${sig.inlineScriptCount} inline <script> block(s), ${sig.inlineHandlerCount} inline event handler attribute(s). Relevant when tightening CSP to remove 'unsafe-inline'.` });

  out.push(sig.missingSRI.length ? {
    level: "warn", title: "Missing Subresource Integrity (SRI)",
    observed: `${sig.missingSRI.length} cross-origin script/style tag(s) without integrity: ${sig.missingSRI.slice(0,3).join(", ")}${sig.missingSRI.length > 3 ? "…" : ""}`,
    why: "If a third-party host (CDN, library provider) is ever compromised or the resource is served via a non-HTTPS/mixed-content path, the browser will execute whatever it returns with no verification, enabling a supply-chain attack against every visitor.",
    recommendation: "Add `integrity` (SRI hash) and `crossorigin` attributes to cross-origin <script>/<link> tags, or self-host the resource."
  } : { level: "pass", title: "Subresource Integrity", observed: "Cross-origin scripts/styles all carry an integrity attribute (or none are cross-origin)." });

  const sensKeys = [...sig.sensitiveStorageKeys.local.map(k => `local:${k}`), ...sig.sensitiveStorageKeys.session.map(k => `session:${k}`)];
  out.push(sensKeys.length ? {
    level: "warn", title: "Sensitive-looking data in Web Storage",
    observed: `Key(s): ${sensKeys.join(", ")}`,
    why: "localStorage/sessionStorage are readable by any JavaScript running on the page's origin. If the app has any XSS vector, tokens/secrets stored here are trivially exfiltrated — unlike an HttpOnly cookie, there is no browser-level protection available for Web Storage.",
    recommendation: "Avoid storing session tokens/secrets in Web Storage; prefer HttpOnly, Secure, SameSite cookies for session material."
  } : { level: "pass", title: "Web Storage", observed: "No obviously sensitive-named keys found." });

  out.push(sig.possibleSecrets.length ? {
    level: "warn", title: "Possible secret material in page source",
    observed: sig.possibleSecrets.map(p => `${p.name} (${p.count}x)`).join(", "),
    why: "Pattern matches resembling API keys/credentials/private key material were found in the rendered HTML. If confirmed genuine, this exposes credentials to anyone who views page source, potentially enabling access to backend services or other systems.",
    recommendation: "Manually verify each match; remove any real secret from client-delivered content and rotate it if it was ever exposed."
  } : { level: "pass", title: "Secrets in HTML", observed: "No obvious secret patterns found (best-effort, not exhaustive)." });

  out.push({ level: "info", title: "Third-party hosts loaded", observed: sig.thirdPartyDomains.length ? `${sig.thirdPartyDomains.length} distinct host(s): ${sig.thirdPartyDomains.slice(0,6).join(", ")}${sig.thirdPartyDomains.length > 6 ? "…" : ""}` : "None detected." });

  out.push(sig.openRedirectParams.length ? {
    level: "warn", title: "Possible open-redirect parameter",
    observed: `URL contains: ${sig.openRedirectParams.join(", ")}`,
    why: "Parameters named like redirect/next/return_url are commonly used to send users onward after an action (e.g. login). If the target is not validated against an allow-list, an attacker can craft a link on this trusted domain that redirects victims to a phishing page — useful in phishing and OAuth-token-theft chains.",
    recommendation: "Validate redirect targets against an allow-list of known-safe paths/hosts, or use indirect reference tokens instead of raw URLs."
  } : { level: "info", title: "Redirect-style parameters", observed: "None found in current URL." });

  return out;
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
        out.push({ level: "info", title: label, observed: `Found (HTTP ${res.status}), ${lineCount} non-empty line(s). Useful for recon (disclosed paths / contact process), not a vulnerability by itself.` });
      } else {
        out.push({ level: "info", title: label, observed: `Not found (HTTP ${res.status}).` });
      }
    } catch (e) {
      out.push({ level: "info", title: label, observed: `Could not fetch (${e.message}).` });
    }
  }
  await tryFetch("/robots.txt", "robots.txt");
  await tryFetch("/.well-known/security.txt", "security.txt");
  return out;
}

// ---------- Main flow ----------
let lastResults = null;

async function runOne(tab) {
  const isHttps = tab.url.startsWith("https:");
  const record = await chrome.runtime.sendMessage({ type: "GET_HEADERS", tabId: tab.id });
  const cookies = await chrome.cookies.getAll({ url: tab.url });
  let pageSignals = null;
  try {
    const [{ result }] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: collectPageSignals });
    pageSignals = result;
  } catch (e) {}
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

  const headerFindings = data.record ? checkHeaders(data.record.headers, data.isHttps) : [{ level: "warn", title: "No response captured", observed: "Reload the page, then click Re-scan." }];
  const cookieInventory = buildCookieInventory(data.cookies);
  const cookieFindings = checkCookies(data.cookies, data.isHttps);
  const pageFindings = data.pageSignals ? pageChecksToFindings(data.pageSignals, data.isHttps) : [{ level: "info", title: "Page-level checks", observed: "Could not run on this tab (restricted page)." }];

  document.getElementById("headers").innerHTML = renderSection(headerFindings);
  document.getElementById("cookieInventory").innerHTML = cookieInventory.length ? renderSection(cookieInventory) : `<div class="empty">No cookies found for this origin.</div>`;
  document.getElementById("cookies").innerHTML = renderSection(cookieFindings);
  document.getElementById("page").innerHTML = renderSection(pageFindings);

  const origin = new URL(tab.url).origin;
  document.getElementById("recon").innerHTML = `<div class="empty">Fetching…</div>`;
  const reconFindings = await runRecon(origin);
  document.getElementById("recon").innerHTML = renderSection(reconFindings);

  document.getElementById("summary").innerHTML = renderSummary([...headerFindings, ...cookieFindings, ...pageFindings, ...reconFindings]);
  lastResults.findings = { headers: headerFindings, cookieInventory, cookies: cookieFindings, page: pageFindings, recon: reconFindings };

  document.getElementById("status").textContent = "";
}

async function scanAllTabs() {
  document.getElementById("status").textContent = "Scanning all tabs…";
  const tabs = await chrome.tabs.query({});
  const results = [];
  for (const tab of tabs) {
    if (!tab.url || !/^https?:/.test(tab.url)) continue;
    const data = await runOne(tab);
    const headerFindings = data.record ? checkHeaders(data.record.headers, data.isHttps) : [];
    const cookieInventory = buildCookieInventory(data.cookies);
    const cookieFindings = checkCookies(data.cookies, data.isHttps);
    const pageFindings = data.pageSignals ? pageChecksToFindings(data.pageSignals, data.isHttps) : [];
    data.findings = { headers: headerFindings, cookieInventory, cookies: cookieFindings, page: pageFindings };
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
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

document.getElementById("refresh").addEventListener("click", run);
document.getElementById("export").addEventListener("click", () => { if (lastResults) downloadJSON(lastResults, "websec-auditor-report.json"); });
document.getElementById("scanAll").addEventListener("click", scanAllTabs);

run();
