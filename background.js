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
  if (msg.type !== "GET_HEADERS") return;
  const tabId = msg.tabId;
  if (tabHeaders.has(tabId)) {
    sendResponse(tabHeaders.get(tabId));
    return;
  }
  chrome.storage.session.get(`tab_${tabId}`).then((res) => {
    sendResponse(res[`tab_${tabId}`] || null);
  });
  return true; // async response
});
