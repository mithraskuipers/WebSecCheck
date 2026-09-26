// ============================================================
// Rendering primitives
// ============================================================
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

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
  const catTag = f.category ? `<span class="cat-tag">${f.category}</span>` : "";
  return `<div class="item">
    <div class="item-head"><span class="badge ${badgeClass}">${f.level.toUpperCase()}</span>${catTag}<span class="item-title">${f.title}</span></div>
    <div class="item-observed">${f.observed}</div>
    ${body}
  </div>`;
}

function tagCategory(findings, category) {
  return (findings || []).map(f => ({ ...f, category }));
}

const CATEGORY_ORDER = ["Security Headers", "Cookies", "Page-Level Checks", "Reconnaissance", "TLS / Certificate"];

// Grouped-by-category view (used when no filters are active) keeps the tool
// readable at a glance; a flat list (used once any filter is applied) is what
// makes "find everything matching X" fast. Category pills stay on every item
// either way so it's always clear which subtopic something belongs to.
function renderResults(items, grouped) {
  if (!items.length) return `<div class="empty">No matching results.</div>`;
  if (!grouped) return items.map(renderItem).join("");
  let html = "";
  CATEGORY_ORDER.forEach((cat) => {
    const group = items.filter(f => f.category === cat);
    if (!group.length) return;
    html += `<div class="group-heading">${cat} (${group.length})</div>` + group.map(renderItem).join("");
  });
  return html;
}

function renderSummary(allFindings) {
  const counts = { pass: 0, warn: 0, fail: 0, info: 0 };
  allFindings.forEach(f => { counts[f.level] = (counts[f.level] || 0) + 1; });
  const box = (cls, label, n) => `<div class="sum-${cls}" data-level="${cls}"><span class="sum-count">${n}</span><span class="sum-label">${label}</span></div>`;
  return box("fail", "FAIL", counts.fail) + box("warn", "WARN", counts.warn) + box("pass", "PASS", counts.pass) + box("info", "INFO", counts.info);
}

// ============================================================
// Header checks
// ============================================================
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

// ============================================================
// Cookie checks — one item per cookie, combining inventory info
// (domain/path/lifetime/value) with the hijacking-risk assessment,
// so each cookie shows up exactly once instead of split across sections.
// ============================================================
const SESSION_LIKE_RE = /(sess|sid|jsessionid|phpsessid|auth|token|jwt|login|account|uid|identity)/i;

function mergeCookieFindings(cookies, isHttps) {
  if (!cookies || cookies.length === 0) {
    return [{ level: "info", title: "No cookies found for this origin", observed: "—" }];
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

    const scopeInfo = `Domain: ${c.domain}${c.hostOnly ? " (host-only)" : " (domain-wide)"} | Path: ${c.path} | ${c.session ? "Session cookie" : `Persistent, expires ${new Date(c.expirationDate * 1000).toLocaleDateString()}`}${isSessionLike ? " | session/auth-like" : ""}`;

    if (level === "pass") {
      return {
        level: "pass", title: `Cookie: ${c.name} — resistant to common hijacking vectors`,
        observed: `Secure, HttpOnly, SameSite=${sameSite}. ${scopeInfo}. Network sniffing, JS/XSS theft, and cross-site riding are all mitigated for this cookie.`,
        value: c.value, valueLength: c.value ? c.value.length : 0, cookieName: c.name
      };
    }

    const whyParts = [];
    const recParts = [];
    if (issues.some(i => i.includes("Secure"))) {
      whyParts.push("Hijacking via network interception: without the Secure flag, the browser will also send this cookie over a plain-HTTP connection to the same host, so anyone on the network path (open Wi-Fi, a malicious proxy, ARP spoofing on a LAN) can capture it and replay it to impersonate the user — no XSS needed.");
      recParts.push("Set the Secure attribute on this cookie.");
    }
    if (issues.some(i => i.includes("HttpOnly"))) {
      whyParts.push("Hijacking via XSS: without HttpOnly, `document.cookie` can read this cookie from JavaScript. Any injected script (stored, reflected, or DOM XSS anywhere on the site) can exfiltrate it to an attacker-controlled server, who then simply sets the same cookie in their own browser to take over the session — the classic 'cookie hijacking' path.");
      recParts.push("Set the HttpOnly attribute so the cookie is inaccessible to JavaScript.");
    }
    if (issues.some(i => i.includes("SameSite"))) {
      whyParts.push("Hijacking-adjacent risk via cross-site requests: a weak/unset SameSite value means this cookie still rides along on requests triggered from another site the victim has open — the precondition for CSRF, and can be chained with other bugs to act as the victim without stealing the value.");
      recParts.push("Set SameSite=Lax (or Strict where the flow allows) unless this cookie needs cross-site delivery, in which case pair SameSite=None with Secure and add CSRF tokens.");
    }
    if (issues.some(i => i.includes("parent domain"))) {
      whyParts.push("Broadened attack surface: this looks like a session/auth cookie but is scoped to the whole parent domain rather than just this host, so it's also sent to (and can potentially be set by) every subdomain. A vulnerability on any single subdomain can be used to steal or overwrite it for the whole domain.");
      recParts.push("Scope session/auth cookies to the specific host that needs them unless true cross-subdomain SSO is required.");
    }
    return {
      level, title: `Cookie: ${c.name}${isSessionLike ? " (session/auth-like)" : ""}`,
      observed: `${issues.join(", ")}. ${scopeInfo}.`,
      why: whyParts.join(" "), recommendation: recParts.join(" "),
      value: c.value, valueLength: c.value ? c.value.length : 0, cookieName: c.name
    };
  });
}

// ============================================================
// Page-level DOM checks (runs inside the page)
// ============================================================
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

// ============================================================
// Reconnaissance (robots.txt / security.txt)
// ============================================================
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

// ============================================================
// TLS / certificate check (manual, uses chrome.debugger + CDP)
// ============================================================
function renderTlsFindings(response) {
  const scopeNote = {
    level: "info", title: "Scope vs. testssl.sh",
    observed: "This reads what the browser itself negotiated for this one connection (protocol, cipher, certificate) via Chrome's DevTools Protocol. It cannot enumerate every protocol version and cipher suite a server would accept, and cannot probe for implementation bugs like Heartbleed, POODLE, ROBOT, or CCS injection — those need raw TLS handshakes crafted outside the browser's TLS stack, which browser extensions have no API to do. For that level of testing, run testssl.sh or sslyze against the host directly."
  };
  if (response.error) return [scopeNote, { level: "fail", title: "TLS/Cert check failed", observed: response.error }];

  const sec = response.data.security;
  const out = [scopeNote];

  const proto = sec.protocol || "unknown";
  const weakProto = /SSL|TLS ?1(\.0|\.1)?\b/i.test(proto) && !/TLS ?1\.[23]/i.test(proto);
  out.push({
    level: weakProto ? "fail" : "pass",
    title: "Negotiated TLS protocol version", observed: proto,
    why: weakProto ? "An outdated protocol version was negotiated for this connection. TLS 1.0/1.1 and any SSL version have known weaknesses and are deprecated by all major standards bodies." : undefined,
    recommendation: weakProto ? "Disable TLS 1.0/1.1 and SSLv3 on the server; support only TLS 1.2 and 1.3." : undefined
  });

  out.push({ level: "info", title: "Negotiated cipher suite", observed: `${sec.cipher || "unknown"}${sec.keyExchange ? `, key exchange: ${sec.keyExchange}${sec.keyExchangeGroup ? " (" + sec.keyExchangeGroup + ")" : ""}` : ""}. Note: this is only what your browser chose from the server's offered list, not the full list the server supports.` });

  const subject = sec.subjectName || "unknown";
  const issuer = sec.issuer || "unknown";
  const selfSigned = subject && issuer && subject === issuer;
  out.push({
    level: selfSigned ? "warn" : "pass",
    title: selfSigned ? "Certificate appears self-signed" : "Certificate issuer",
    observed: `Subject: ${subject} | Issuer: ${issuer}`,
    why: selfSigned ? "A self-signed certificate is not validated by a public CA, so nothing prevents an attacker from presenting their own self-signed cert in a MITM position unless the client has been specifically configured to pin/trust this exact cert." : undefined,
    recommendation: selfSigned ? "Use a certificate from a trusted CA for anything beyond internal/dev use, or ensure clients pin the expected certificate." : undefined
  });

  if (sec.validTo) {
    const now = Date.now() / 1000;
    const daysLeft = Math.floor((sec.validTo - now) / 86400);
    let level = "pass", why, rec;
    if (sec.validTo < now) { level = "fail"; why = "The certificate has already expired. Browsers will show hard trust errors, and any client-side pinning or automation expecting a valid chain will fail."; rec = "Renew the certificate immediately."; }
    else if (daysLeft < 14) { level = "fail"; why = `Certificate expires in ${daysLeft} day(s). Expiry this close is a real operational risk (site-down / trust-error incident).`; rec = "Renew now and verify auto-renewal (e.g. ACME/Let's Encrypt) is actually working."; }
    else if (daysLeft < 30) { level = "warn"; why = `Certificate expires in ${daysLeft} day(s).`; rec = "Schedule renewal well before expiry."; }
    out.push({
      level, title: "Certificate validity window",
      observed: `Valid from ${new Date(sec.validFrom * 1000).toISOString().slice(0,10)} to ${new Date(sec.validTo * 1000).toISOString().slice(0,10)} (${daysLeft} day(s) remaining)`,
      why, recommendation: rec
    });
  }

  if (Array.isArray(sec.sanList)) {
    out.push({ level: "info", title: "Subject Alternative Names", observed: `${sec.sanList.length} SAN(s): ${sec.sanList.slice(0,8).join(", ")}${sec.sanList.length > 8 ? "…" : ""}` });
  }
  if (sec.certificateTransparencyCompliance) {
    out.push({ level: sec.certificateTransparencyCompliance === "compliant" ? "pass" : "info", title: "Certificate Transparency compliance", observed: sec.certificateTransparencyCompliance });
  }

  return out;
}

// ============================================================
// Filter engine
// ============================================================
let filterState = { level: null, category: "all", search: "", cookieName: null };
let taggedBase = [];   // headers + cookies + page + recon, tagged
let tlsTagged = [];    // TLS findings, tagged (empty until run)

function allTagged() { return [...taggedBase, ...tlsTagged]; }

// One chip per distinct cookie found on the scanned page, so a page with several
// cookies (e.g. MpSslSecurity, __mpx) can be narrowed to one with a single click
// instead of typing the exact name into search.
function renderCookieNameChips() {
  const names = [...new Set(taggedBase.filter(f => f.category === "Cookies" && f.cookieName).map(f => f.cookieName))];
  const container = document.getElementById("cookieNameFilters");
  const label = document.getElementById("cookieChipLabel");
  if (!names.length) {
    container.innerHTML = "";
    label.style.display = "none";
    return;
  }
  label.style.display = "block";
  container.innerHTML = names.map(n => `<button class="qf-chip cookie-chip" data-cookie="${escapeHtml(n)}">${escapeHtml(n)}</button>`).join("");
}

function applyFilters() {
  const all = allTagged();
  const q = filterState.search.trim().toLowerCase();
  const filtered = all.filter(f => {
    if (filterState.level && f.level !== filterState.level) return false;
    if (filterState.category !== "all" && f.category !== filterState.category) return false;
    if (filterState.cookieName && f.cookieName !== filterState.cookieName) return false;
    if (q) {
      const hay = `${f.title} ${f.observed} ${f.category || ""}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  const noFiltersActive = !filterState.level && filterState.category === "all" && !q && !filterState.cookieName;
  document.getElementById("results").innerHTML = renderResults(filtered, noFiltersActive);

  document.querySelectorAll("#summary > div").forEach(el => el.classList.toggle("active-filter", el.dataset.level === filterState.level));
  document.querySelectorAll("#quickFilters .qf-chip").forEach(el => el.classList.toggle("active", el.dataset.category === filterState.category));
  document.querySelectorAll("#cookieNameFilters .cookie-chip").forEach(el => el.classList.toggle("active", el.dataset.cookie === filterState.cookieName));

  const chips = [];
  if (filterState.level) chips.push({ key: "level", label: filterState.level.toUpperCase() });
  if (filterState.category !== "all") chips.push({ key: "category", label: filterState.category });
  if (filterState.cookieName) chips.push({ key: "cookieName", label: `Cookie: ${filterState.cookieName}` });
  if (q) chips.push({ key: "search", label: `"${filterState.search}"` });
  const bar = document.getElementById("activeFiltersBar");
  if (!chips.length) {
    bar.innerHTML = "";
  } else {
    bar.innerHTML = chips.map(c => `<span class="chip" data-key="${c.key}">${escapeHtml(c.label)}<button data-clear="${c.key}">×</button></span>`).join("") +
      `<button class="clear-all" id="clearAllFilters">Clear all</button>`;
  }
}

document.getElementById("summary").addEventListener("click", (e) => {
  const box = e.target.closest("[data-level]");
  if (!box) return;
  filterState.level = filterState.level === box.dataset.level ? null : box.dataset.level;
  applyFilters();
});
document.getElementById("quickFilters").addEventListener("click", (e) => {
  const chip = e.target.closest("[data-category]");
  if (!chip) return;
  filterState.category = filterState.category === chip.dataset.category ? "all" : chip.dataset.category;
  if (filterState.category !== "Cookies") filterState.cookieName = null;
  applyFilters();
});
document.getElementById("cookieNameFilters").addEventListener("click", (e) => {
  const chip = e.target.closest("[data-cookie]");
  if (!chip) return;
  if (filterState.cookieName === chip.dataset.cookie) {
    filterState.cookieName = null;
  } else {
    filterState.cookieName = chip.dataset.cookie;
    filterState.category = "Cookies";
  }
  applyFilters();
});
document.getElementById("searchFilter").addEventListener("input", (e) => {
  filterState.search = e.target.value;
  applyFilters();
});
document.getElementById("activeFiltersBar").addEventListener("click", (e) => {
  if (e.target.id === "clearAllFilters") {
    filterState = { level: null, category: "all", search: "", cookieName: null };
    document.getElementById("searchFilter").value = "";
    applyFilters();
    return;
  }
  const clearKey = e.target.dataset.clear;
  if (!clearKey) return;
  if (clearKey === "level") filterState.level = null;
  if (clearKey === "category") { filterState.category = "all"; filterState.cookieName = null; }
  if (clearKey === "cookieName") filterState.cookieName = null;
  if (clearKey === "search") { filterState.search = ""; document.getElementById("searchFilter").value = ""; }
  applyFilters();
});

// ============================================================
// Main flow
// ============================================================
let lastResults = null;
let currentTabId = null;

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
  currentTabId = tab.id;
  document.getElementById("url").textContent = tab.url;
  const btn = document.getElementById("refresh");
  btn.disabled = true;

  // TLS/cert check runs first and by default as part of every scan. It reloads
  // the tab and briefly shows Chrome's "being debugged" banner (chrome.debugger +
  // DevTools Protocol is the only way to read the actually-negotiated protocol/
  // cipher/certificate — see the scope note in the results). Header/cookie/page/
  // recon checks then run against that same freshly-loaded page.
  document.getElementById("status").textContent = 'Running TLS/cert check — the tab will reload and Chrome will show a "being debugged" banner briefly…';
  let tlsFindingsResult;
  try {
    const response = await chrome.runtime.sendMessage({ type: "RUN_TLS_CHECK", tabId: tab.id });
    tlsFindingsResult = renderTlsFindings(response);
  } catch (e) {
    tlsFindingsResult = [{ level: "fail", title: "TLS/Cert check failed", observed: e.message }];
  }
  tlsTagged = tagCategory(tlsFindingsResult, "TLS / Certificate");

  document.getElementById("status").textContent = "Scanning headers, cookies, page, and recon…";
  const data = await runOne(tab);
  lastResults = data;

  const headerFindings = data.record ? checkHeaders(data.record.headers, data.isHttps) : [{ level: "warn", title: "No response captured", observed: "Click Scan again." }];
  const cookieFindings = mergeCookieFindings(data.cookies, data.isHttps);
  const pageFindings = data.pageSignals ? pageChecksToFindings(data.pageSignals, data.isHttps) : [{ level: "info", title: "Page-level checks", observed: "Could not run on this tab (restricted page)." }];

  const origin = new URL(tab.url).origin;
  const reconFindings = await runRecon(origin);

  taggedBase = [
    ...tagCategory(headerFindings, "Security Headers"),
    ...tagCategory(cookieFindings, "Cookies"),
    ...tagCategory(pageFindings, "Page-Level Checks"),
    ...tagCategory(reconFindings, "Reconnaissance")
  ];
  document.getElementById("summary").innerHTML = renderSummary(allTagged());
  renderCookieNameChips();
  filterState = { level: null, category: filterState.category, search: filterState.search, cookieName: null }; // keep category/search sticky across scans, reset level + cookie pick
  applyFilters();

  lastResults.findings = { headers: headerFindings, cookies: cookieFindings, page: pageFindings, recon: reconFindings, tls: tlsFindingsResult };
  document.getElementById("status").textContent = "";
  btn.disabled = false;
}

async function scanAllTabs() {
  document.getElementById("status").textContent = "Scanning all tabs…";
  const tabs = await chrome.tabs.query({});
  const results = [];
  for (const tab of tabs) {
    if (!tab.url || !/^https?:/.test(tab.url)) continue;
    const data = await runOne(tab);
    const headerFindings = data.record ? checkHeaders(data.record.headers, data.isHttps) : [];
    const cookieFindings = mergeCookieFindings(data.cookies, data.isHttps);
    const pageFindings = data.pageSignals ? pageChecksToFindings(data.pageSignals, data.isHttps) : [];
    data.findings = { headers: headerFindings, cookies: cookieFindings, page: pageFindings };
    results.push(data);
  }
  lastResults = { multiTab: true, tabs: results };
  downloadJSON(lastResults, "websec-auditor-all-tabs.json");
  document.getElementById("status").textContent = `Scanned ${results.length} tab(s), exported JSON. (TLS/Cert check is single-tab only, run it separately per tab.)`;
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

// Nothing runs automatically on popup open — the TLS/cert check reloads the tab
// and briefly shows Chrome's debugger banner, so that only happens once the user
// deliberately clicks Scan. This just previews which tab Scan would target.
async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab && /^https?:/.test(tab.url || "")) {
    currentTabId = tab.id;
    document.getElementById("url").textContent = tab.url;
    document.getElementById("results").innerHTML = `<div class="empty">Click Scan to run header, cookie, page-level, TLS/cert, and recon checks against this tab.</div>`;
  } else {
    document.getElementById("url").textContent = "Unsupported page (not http/https).";
    document.getElementById("refresh").disabled = true;
  }
}
init();
