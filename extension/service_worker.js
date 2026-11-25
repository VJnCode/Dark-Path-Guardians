// Background service worker: the only place that talks to the backend.
const DEFAULT_BACKEND = "http://127.0.0.1:8000";

async function backendUrl() {
  const { backend } = await chrome.storage.local.get("backend");
  return backend || DEFAULT_BACKEND;
}

async function analyze(tabId, url) {
  await chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] });
  const { elements } = await chrome.tabs.sendMessage(tabId, { action: "extract" });

  const res = await fetch(`${await backendUrl()}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-DPG-Client": "extension" },
    body: JSON.stringify({ url, elements, mode: "hybrid", include_threat: true }),
  });
  if (!res.ok) throw new Error(`Backend returned ${res.status}`);
  const result = await res.json();

  await chrome.tabs.sendMessage(tabId, { action: "highlight", findings: result.findings });
  result.element_count = elements.length;
  await chrome.storage.session.set({ [`result:${tabId}`]: { url, result } });
  return result;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only accept messages from our own extension pages (the popup).
  if (sender.id !== chrome.runtime.id || sender.tab) return;
  if (msg.action === "analyze") {
    analyze(msg.tabId, msg.url)
      .then((result) => sendResponse({ result }))
      .catch((e) => sendResponse({ error: e.message || String(e) }));
    return true;
  }
});

// Forget cached results when a tab navigates or closes.
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "loading") chrome.storage.session.remove(`result:${tabId}`);
});
chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove(`result:${tabId}`));

// ------------------------------------------------------------ sandbox

function openSandbox(url) {
  chrome.tabs.create({ url: chrome.runtime.getURL(`sandbox.html?url=${encodeURIComponent(url)}`) });
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "dpg-sandbox", title: "Open link in secure sandbox", contexts: ["link"] });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === "dpg-sandbox" && info.linkUrl) openSandbox(info.linkUrl);
});
