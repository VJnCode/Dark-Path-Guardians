// Injected on demand (activeTab + scripting) when the user opens the popup.
// Extracts page elements for the backend and highlights the findings it returns.
(() => {
  if (window.__dpgLoaded) return;
  window.__dpgLoaded = true;

  const MAX_ELEMENTS = 500;
  const MAX_TEXT = 300;
  const CURRENCY = /([$€£₹¥]|\bUSD|\bEUR|\bGBP|\bINR|\bRs\.?)\s?\d|\d\s?(€|EUR|USD)\b/;
  const TIME_LIKE = /\b\d{1,2}\s*[:h]\s*\d{2}(\s*[:m]\s*\d{2})?\b|\b\d+\s*(hours?|hrs?|minutes?|mins?|seconds?|secs?)\b/i;
  const CONSENT_CONTAINER = /cookie|consent|gdpr|cmp|privacy-banner|onetrust|didomi|usercentrics/i;
  const AD_TOKEN = /(^|[\s_-])(ad|ads|adv|advert|advertisement|sponsor|sponsored|promoted|adsbygoogle)([\s_-]|$)/i;

  const clean = (s) => (s || "").replace(/\s+/g, " ").trim();
  const cut = (s, n = MAX_TEXT) => clean(s).slice(0, n);

  function isVisible(el) {
    if (!el.getClientRects().length) return false;
    const st = getComputedStyle(el);
    return st.visibility !== "hidden" && st.display !== "none" && parseFloat(st.opacity) > 0.05;
  }

  // Unique CSS selector: an id if it is unique, otherwise a tag:nth-of-type path.
  function selectorFor(el) {
    if (el.id && document.querySelectorAll("#" + CSS.escape(el.id)).length === 1) {
      return "#" + CSS.escape(el.id);
    }
    const parts = [];
    let node = el;
    while (node && node.nodeType === 1 && node !== document.body && parts.length < 25) {
      if (node.id && document.querySelectorAll("#" + CSS.escape(node.id)).length === 1) {
        parts.unshift("#" + CSS.escape(node.id));
        return parts.join(" > ");
      }
      const tag = node.tagName.toLowerCase();
      const siblings = node.parentElement
        ? [...node.parentElement.children].filter((c) => c.tagName === node.tagName)
        : [];
      parts.unshift(siblings.length > 1 ? `${tag}:nth-of-type(${siblings.indexOf(node) + 1})` : tag);
      node = node.parentElement;
    }
    return "body > " + parts.join(" > ");
  }

  // Text that belongs to the element itself, not its children.
  function ownText(el) {
    let t = "";
    for (const n of el.childNodes) if (n.nodeType === 3) t += n.textContent;
    return clean(t);
  }

  function consentContainer(el) {
    for (let n = el; n && n !== document.body; n = n.parentElement) {
      if (CONSENT_CONTAINER.test((n.id || "") + " " + (n.className?.toString?.() || "")) ||
          n.getAttribute?.("aria-label")?.match(/cookie|consent|privacy/i)) return n;
    }
    return null;
  }

  // Text of the nearest container that says noticeably more than the element itself.
  // (A button row like "Manage Settings Agree" is too small; the banner around it is what we want.)
  function nearText(el) {
    const consent = consentContainer(el);
    if (consent) return cut(consent.innerText, 600);
    const own = clean(el.innerText || el.value || "").length;
    for (let n = el.parentElement, depth = 0; n && n !== document.body && depth < 6; n = n.parentElement, depth++) {
      const t = clean(n.innerText);
      if (t.length > own + 60) return cut(t, 400);
    }
    return "";
  }

  function adHint(el) {
    for (let n = el, depth = 0; n && n !== document.body && depth < 5; n = n.parentElement, depth++) {
      const attrs = (n.id || "") + " " + (n.className?.toString?.() || "");
      if (AD_TOKEN.test(attrs) || n.hasAttribute("data-ad") || n.hasAttribute("data-ad-slot")) return true;
    }
    return false;
  }

  function labelFor(input) {
    if (input.labels && input.labels.length) return cut(input.labels[0].innerText);
    const wrap = input.closest("label");
    if (wrap) return cut(wrap.innerText);
    return cut(input.getAttribute("aria-label") || input.parentElement?.innerText || "");
  }

  async function extract() {
    const out = [];
    const seen = new Set();
    const add = (el, item) => {
      const selector = selectorFor(el);
      if (selector.length > 1000) return; // the API rejects longer selectors
      const key = selector + "|" + item.kind;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ selector, near_text: "", href: "", label: "", ad_hint: false, changing: false, ...item });
    };

    // 1. Checkboxes and radios (always kept: they are few and important).
    for (const input of document.querySelectorAll('input[type=checkbox], input[type=radio]')) {
      const visibleEl = isVisible(input) ? input : input.closest("label");
      if (!visibleEl || !isVisible(visibleEl)) continue;
      add(input, { kind: input.type, text: labelFor(input), label: labelFor(input),
                   checked: input.checked, near_text: nearText(input) });
    }

    // 2. Buttons and links.
    const clickable = document.querySelectorAll(
      'button, [role=button], input[type=submit], input[type=button], a[href]');
    for (const el of clickable) {
      if (!isVisible(el)) continue;
      const text = cut(el.innerText || el.value || el.getAttribute("aria-label") || "", 150);
      if (!text) continue;
      add(el, { kind: el.tagName === "A" && el.getAttribute("role") !== "button" ? "link" : "button",
                text, near_text: nearText(el), href: (el.href || "").slice(0, 500), ad_hint: adHint(el) });
    }

    // 3. Text blocks, prices, timer candidates and consent banners.
    const timerCandidates = [];
    const seenText = new Set();
    const blocks = document.querySelectorAll("p, span, div, li, h1, h2, h3, h4, h5, h6, strong, b, em, small, label, td, dd");
    for (const el of blocks) {
      const own = ownText(el);
      if (own.length < 3 || !isVisible(el)) continue;
      // Small containers keep their full text ("Only <b>2</b> left"); big ones only their own text.
      const full = clean(el.innerText);
      const text = full.length <= MAX_TEXT ? full : cut(own);
      if (seenText.has(text)) continue; // nested elements with the same text
      seenText.add(text);
      if (CURRENCY.test(own)) {
        // Use the whole row so the label ("Service fee") travels with the amount.
        const row = el.closest("tr, li, dl > div, [class*=row], [class*=line]") || el.parentElement || el;
        add(el, { kind: "price", text: cut(row.innerText, 150) });
      } else if (TIME_LIKE.test(own)) {
        timerCandidates.push({ el, before: el.innerText });
      } else {
        add(el, { kind: "text", text, near_text: nearText(el), ad_hint: adHint(el) });
      }
    }
    for (const el of document.querySelectorAll("div, section, aside, dialog, [role=dialog]")) {
      const attrs = (el.id || "") + " " + (el.className?.toString?.() || "");
      if (CONSENT_CONTAINER.test(attrs) && isVisible(el) && clean(el.innerText).length > 20) {
        add(el, { kind: "banner", text: cut(el.innerText, 600) });
      }
    }

    // A real countdown changes between two samples ~1.1s apart.
    if (timerCandidates.length) {
      await new Promise((r) => setTimeout(r, 1100));
      for (const { el, before } of timerCandidates.slice(0, 50)) {
        const changing = el.innerText !== before;
        add(el, { kind: changing ? "timer" : "text", text: cut(el.innerText), near_text: nearText(el), changing });
      }
    }

    // Keep the most useful kinds first if the page is huge.
    const priority = { checkbox: 0, radio: 0, timer: 1, price: 2, banner: 3, button: 4, link: 5, text: 6 };
    out.sort((a, b) => priority[a.kind] - priority[b.kind]);
    return out.slice(0, MAX_ELEMENTS);
  }

  // ------------------------------------------------------------ highlighting

  const STYLE_ID = "dpg-style";
  function ensureStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = `
      [data-dpg-flag] { outline: 3px solid #e5484d !important; outline-offset: 2px !important; }
      [data-dpg-flag="medium"] { outline-color: #f5a524 !important; }
      [data-dpg-focus] { outline-width: 5px !important; }`;
    document.documentElement.appendChild(style);
  }

  function clearHighlights() {
    for (const el of document.querySelectorAll("[data-dpg-flag]")) {
      el.removeAttribute("data-dpg-flag");
      el.removeAttribute("data-dpg-focus");
      if (el.dataset.dpgTitle !== undefined) {
        el.title = el.dataset.dpgTitle;
        delete el.dataset.dpgTitle;
      }
    }
  }

  function highlight(findings) {
    ensureStyle();
    clearHighlights();
    let count = 0;
    for (const f of findings) {
      let el;
      try { el = document.querySelector(f.element_selector); } catch { continue; }
      if (!el) continue;
      if (el.dataset.dpgTitle === undefined) el.dataset.dpgTitle = el.title || "";
      el.setAttribute("data-dpg-flag", f.confidence >= 0.8 ? "high" : "medium");
      const label = f.pattern_type.replace(/_/g, " ");
      el.title = `[Dark pattern: ${label}] ${f.explanation}`;
      count++;
    }
    return count;
  }

  function focus(selector) {
    document.querySelectorAll("[data-dpg-focus]").forEach((e) => e.removeAttribute("data-dpg-focus"));
    let el;
    try { el = document.querySelector(selector); } catch { return false; }
    if (!el) return false;
    el.setAttribute("data-dpg-focus", "");
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    return true;
  }

  // Also used outside the extension (eval capture, sandbox runner) via Playwright.
  window.__dpgExtract = extract;
  if (!globalThis.chrome?.runtime?.onMessage) return;

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.action === "extract") {
      extract().then((elements) => sendResponse({ elements }));
      return true; // async response
    }
    if (msg.action === "highlight") sendResponse({ count: highlight(msg.findings || []) });
    if (msg.action === "focus") sendResponse({ ok: focus(msg.selector) });
    if (msg.action === "clear") { clearHighlights(); sendResponse({ ok: true }); }
  });
})();
