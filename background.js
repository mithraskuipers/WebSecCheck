// Captures response headers for the top-level document of each tab
// and keeps them available for the popup to read.

const tabHeaders = new Map();

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== "main_frame") return;
    const headers = {};
    for (const h of details.responseHeaders || []) {
      headers[h.name.toLowerCase()] = h.value;
    }
    const record = {
      url: details.url,
      statusCode: details.statusCode,
      headers,
      capturedAt: Date.now()
    };
    tabHeaders.set(details.tabId, record);
    chrome.storage.session.set({ [`tab_${details.tabId}`]: record }).catch(() => {});
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

chrome.tabs.onRemoved.addListener((tabId) => {
  tabHeaders.delete(tabId);
  chrome.storage.session.remove(`tab_${tabId}`).catch(() => {});
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_HEADERS") {
    const tabId = msg.tabId;
    if (tabHeaders.has(tabId)) {
      sendResponse(tabHeaders.get(tabId));
      return;
    }
    chrome.storage.session.get(`tab_${tabId}`).then((res) => {
      sendResponse(res[`tab_${tabId}`] || null);
    });
    return true; // async response
  }

  if (msg.type === "RUN_TLS_CHECK") {
    runTlsCheck(msg.tabId)
      .then((data) => sendResponse({ data }))
      .catch((err) => sendResponse({ error: err.message }));
    return true; // async response
  }
});

// Uses the Chrome DevTools Protocol (via chrome.debugger) to read what the browser
// actually negotiated for the top-level document: TLS protocol version, cipher, and
// certificate details. This shows a "being debugged" banner in Chrome while attached;
// it detaches itself as soon as it has captured one Document response or after a
// 10s timeout. It reloads the tab, so an active request in progress on that tab
// will be interrupted.
function runTlsCheck(tabId) {
  return new Promise((resolve, reject) => {
    let settled = false;

    function cleanup() {
      chrome.debugger.onEvent.removeListener(listener);
      chrome.debugger.sendCommand({ tabId }, "Network.disable", {}, () => {
        chrome.debugger.detach({ tabId }, () => {});
      });
    }

    function listener(source, method, params) {
      if (source.tabId !== tabId || settled) return;
      if (method === "Network.responseReceived" && params.type === "Document" && params.response && params.response.securityDetails) {
        settled = true;
        cleanup();
        resolve({
          url: params.response.url,
          protocol: params.response.protocol,
          securityState: params.response.securityState,
          security: params.response.securityDetails
        });
      }
    }

    chrome.debugger.attach({ tabId }, "1.3", () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      chrome.debugger.onEvent.addListener(listener);
      chrome.debugger.sendCommand({ tabId }, "Network.enable", {}, () => {
        chrome.tabs.reload(tabId, {}, () => {});
      });
    });

    setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error("Timed out waiting for a secure document response (10s). Make sure the tab is on an https:// page, then try again."));
    }, 10000);
  });
}

