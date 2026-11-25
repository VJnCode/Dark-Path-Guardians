// Popup: asks the service worker to analyze the active tab and renders the result.
// All page-derived strings are rendered with textContent, never innerHTML.

const $ = (id) => document.getElementById(id);
const LABELS = {
  fake_urgency: "Fake urgency",
  fake_scarcity: "Fake scarcity",
  preselected_option: "Pre-checked option",
  hidden_fees: "Hidden fees",
  confirmshaming: "Confirmshaming",
  forced_consent: "Forced consent",
  disguised_ad: "Disguised ad",
};
const SIGNAL_LABELS = {
  safe_browsing: "Safe Browsing",
  domain_age: "Domain age",
  ssl: "HTTPS certificate",
  redirects: "Redirects",
};

let tab;

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function setScore(score) {
  $("score").textContent = String(score);
  $("gauge-fill").setAttribute("stroke-dasharray", `${score} 100`);
  const level = score >= 60 ? "high" : score >= 25 ? "medium" : "low";
  $("gauge").dataset.level = level;
  $("verdict").textContent = { high: "High risk", medium: "Some risk", low: "Low risk" }[level];
}

function renderFindings(findings) {
  const list = $("findings");
  list.replaceChildren();
  $("finding-count").textContent = findings.length ? String(findings.length) : "";
  if (!findings.length) {
    list.append(el("li", "empty", "No dark patterns found on this page."));
    return;
  }
  for (const f of findings) {
    const item = el("li", `finding ${f.confidence >= 0.8 ? "high" : "medium"}`);
    const head = el("div", "row");
    head.append(el("strong", "", LABELS[f.pattern_type] || f.pattern_type));
    head.append(el("span", "badge", `${Math.round(f.confidence * 100)}% · ${f.source}`));
    item.append(head, el("p", "explain", f.explanation));
    item.title = "Show on page";
    item.addEventListener("click", () =>
      chrome.tabs.sendMessage(tab.id, { action: "focus", selector: f.element_selector }));
    list.append(item);
  }
}

function renderSignals(threat) {
  const list = $("signals");
  list.replaceChildren();
  if (!threat) {
    list.append(el("li", "empty", "Not checked for this page (not a public http(s) address)."));
    return;
  }
  for (const s of threat.signals) {
    const item = el("li", `signal ${s.status}`);
    const head = el("div", "row");
    head.append(el("strong", "", SIGNAL_LABELS[s.name] || s.name));
    head.append(el("span", `pill ${s.status}`, s.status));
    item.append(head, el("p", "explain", s.detail));
    list.append(item);
  }
}

function render(result) {
  setScore(result.risk_score);
  renderFindings(result.findings);
  renderSignals(result.threat);
  const llm = result.llm_used ? "rules + LLM" : result.llm_error ? "rules only (LLM unavailable)" : "rules";
  $("status").textContent = `${result.element_count ?? "?"} elements checked · ${llm}`;
}

function showError(message) {
  $("verdict").textContent = "Could not scan";
  $("status").textContent = message;
  $("score").textContent = "–";
  $("gauge-fill").setAttribute("stroke-dasharray", "0 100");
  $("findings").replaceChildren();
  $("signals").replaceChildren();
}

async function scan(force = false) {
  $("verdict").textContent = "Scanning…";
  $("status").textContent = "";
  $("rescan").disabled = true;
  try {
    if (!force) {
      const cached = (await chrome.storage.session.get(`result:${tab.id}`))[`result:${tab.id}`];
      if (cached && cached.url === tab.url) return render(cached.result);
    }
    const reply = await chrome.runtime.sendMessage({ action: "analyze", tabId: tab.id, url: tab.url });
    if (!reply) throw new Error("No response from the extension's background worker. Try reopening the popup.");
    if (reply.error) throw new Error(reply.error);
    render(reply.result);
  } catch (e) {
    const msg = String(e.message || e);
    showError(/Cannot access|chrome:\/\/|extensions gallery/i.test(msg)
      ? "This page can't be scanned (browser-internal page)."
      : /Failed to fetch|NetworkError/i.test(msg)
        ? "Backend not reachable at 127.0.0.1:8000. Is `docker compose up` running?"
        : msg);
  } finally {
    $("rescan").disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  $("page-url").textContent = tab?.url ? new URL(tab.url).hostname : "";
  $("rescan").addEventListener("click", () => scan(true));
  if (/^https?:/.test(tab?.url || "")) $("sandbox-url").value = tab.url;
  $("sandbox").addEventListener("click", () => {
    const url = $("sandbox-url").value.trim();
    if (!/^https?:\/\//i.test(url)) {
      $("sandbox-url").focus();
      return;
    }
    chrome.tabs.create({ url: chrome.runtime.getURL(`sandbox.html?url=${encodeURIComponent(url)}`) });
  });
  if (tab) scan();
});
