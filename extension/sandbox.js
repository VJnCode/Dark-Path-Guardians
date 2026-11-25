// Sandbox page: starts a session, shows the verdict first, then lets the user view the page.
// All server-provided strings are rendered with textContent.

const BACKEND_DEFAULT = "http://127.0.0.1:8000";
const $ = (id) => document.getElementById(id);
const FEATURE_LABELS = {
  redirects: "Redirects",
  redirect_domains: "Domains in redirect chain",
  left_target_domain: "Ended on a different site",
  requests: "Network requests",
  third_party_hosts: "Third-party hosts",
  download_attempts: "Download attempts (blocked)",
  popups: "Popups opened",
  blocked_requests: "Requests refused by the sandbox",
};
const VERDICT_TEXT = { safe: "Looks safe", suspicious: "Suspicious", block: "Blocked: likely harmful" };

let backend = BACKEND_DEFAULT;
let session = null;
let poll = null;
let tick = null;

function li(text) {
  const node = document.createElement("li");
  node.textContent = text;
  return node;
}

function showError(message) {
  $("progress").hidden = true;
  $("error").hidden = false;
  $("error").textContent = message;
  clearInterval(poll);
}

function setStep(status) {
  const order = ["starting", "analyzing", "ready"];
  const idx = order.indexOf(status);
  $("step-start").className = idx >= 0 ? "done" : "active";
  $("step-load").className = idx >= 1 ? "done" : idx === 0 ? "active" : "";
  $("step-analyze").className = idx >= 2 ? "done" : idx === 1 ? "active" : "";
}

function renderVerdict(s) {
  const v = s.verdict;
  $("progress").hidden = true;
  $("result").hidden = false;
  $("verdict").textContent = VERDICT_TEXT[v.level];
  $("verdict").dataset.level = v.level;
  $("score").textContent = `Risk ${v.score}/100`;
  $("final-url").textContent = s.final_url && s.final_url !== s.url ? `Ended up at: ${s.final_url}` : "";
  $("reasons").replaceChildren(...v.reasons.map(li));
  const dl = $("features");
  dl.replaceChildren();
  for (const [key, label] of Object.entries(FEATURE_LABELS)) {
    if (!(key in v.features)) continue;
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    const value = v.features[key];
    dd.textContent = typeof value === "boolean" ? (value ? "yes" : "no") : String(value);
    dl.append(dt, dd);
  }
  const blocked = v.level === "block";
  $("override").hidden = !blocked;
  $("open").disabled = blocked;
}

function renderEvents(events) {
  if (!events?.length) return;
  $("events-card").hidden = false;
  const text = {
    download_blocked: (e) => `Download blocked: ${e.url}`,
    navigation: (e) => `Navigated to ${e.url}`,
    popup: (e) => `Popup opened: ${e.url}`,
  };
  $("events").replaceChildren(...events.slice(-20).reverse().map((e) => li((text[e.type] || (() => e.type))(e))));
}

function startCountdown() {
  clearInterval(tick);
  tick = setInterval(() => {
    const left = Math.max(0, Math.round(session.expires_at - Date.now() / 1000));
    $("countdown").textContent = left ? `Session ends in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}` : "Session ended";
    if (!left) {
      clearInterval(tick);
      clearInterval(poll);
      $("open").disabled = true;
      $("end").disabled = true;
    }
  }, 1000);
}

async function refresh() {
  const res = await fetch(`${backend}/sandbox/${session.id}?token=${encodeURIComponent(session.token)}`);
  if (res.status === 404) return showError("The sandbox session has ended.");
  const s = await res.json();
  session = { ...session, ...s };
  setStep(s.status);
  if (s.status === "error") return showError(s.error || "The sandbox could not load this page.");
  if (s.status === "ready") {
    if ($("result").hidden) renderVerdict(s);
    renderEvents(s.events);
  }
}

async function start() {
  const url = new URLSearchParams(location.search).get("url") || "";
  $("target").textContent = url;
  document.title = `Sandbox: ${url}`;
  const stored = await chrome.storage.local.get("backend");
  backend = stored.backend || BACKEND_DEFAULT;

  let res;
  try {
    res = await fetch(`${backend}/sandbox`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-DPG-Client": "extension" },
      body: JSON.stringify({ url }),
    });
  } catch {
    return showError(`Backend not reachable at ${backend}. Is \`docker compose up\` running?`);
  }
  if (!res.ok) {
    const detail = (await res.json().catch(() => ({}))).detail;
    return showError(typeof detail === "string" ? detail : `Could not start the sandbox (HTTP ${res.status}).`);
  }
  session = await res.json();
  setStep(session.status);
  startCountdown();
  poll = setInterval(() => refresh().catch(() => {}), 1500);
}

$("override-check").addEventListener("change", (e) => { $("open").disabled = !e.target.checked; });
$("open").addEventListener("click", () => {
  if (session?.view_url) window.open(`${backend}${session.view_url}`, "_blank", "noopener");
});
$("end").addEventListener("click", async () => {
  await fetch(`${backend}/sandbox/${session.id}?token=${encodeURIComponent(session.token)}`,
              { method: "DELETE", headers: { "X-DPG-Client": "extension" } }).catch(() => {});
  clearInterval(poll);
  clearInterval(tick);
  $("open").disabled = true;
  $("end").disabled = true;
  $("countdown").textContent = "Session ended. The container has been destroyed.";
});
window.addEventListener("pagehide", () => {
  // Best effort: closing this tab ends the session early. The server-side timeout is the real guarantee.
  if (session) {
    fetch(`${backend}/sandbox/${session.id}?token=${encodeURIComponent(session.token)}`,
          { method: "DELETE", headers: { "X-DPG-Client": "extension" }, keepalive: true }).catch(() => {});
  }
});

start();
