"""Capture page snapshots for the manual page set.

Loads each URL in headless Chromium (Playwright), runs the extension's own extract() from
extension/content.js, and saves the elements to eval/manual/snapshots/<id>.json. New pages are
added to eval/manual/pages.jsonl with empty labels; existing labels are never overwritten.

    pip install playwright && python -m playwright install chromium
    python eval/capture.py                     # every URL in eval/manual/urls.txt not yet captured
    python eval/capture.py --force some-id     # re-capture one page
"""
import argparse
import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

HERE = Path(__file__).parent
ROOT = HERE.parent
MANUAL = HERE / "manual"
URLS = MANUAL / "urls.txt"
PAGES = MANUAL / "pages.jsonl"
SNAPSHOTS = MANUAL / "snapshots"
CONTENT_JS = (ROOT / "extension" / "content.js").read_text(encoding="utf-8")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0.0.0 Safari/537.36")


def page_id(url: str) -> str:
    parts = urlsplit(url)
    slug = (parts.hostname or "page").removeprefix("www.") + parts.path
    return re.sub(r"[^a-z0-9]+", "-", slug.lower()).strip("-")[:60]


def read_urls() -> list[tuple[str, str]]:
    out = []
    for line in URLS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        url, _, note = line.partition(" #")
        out.append((url.strip(), note.strip()))
    return out


def load_pages() -> dict[str, dict]:
    if not PAGES.exists():
        return {}
    rows = [json.loads(x) for x in PAGES.read_text(encoding="utf-8").splitlines() if x.strip()]
    return {r["id"]: r for r in rows}


def save_pages(pages: dict[str, dict]) -> None:
    PAGES.write_text("".join(json.dumps(p, ensure_ascii=False) + "\n" for p in pages.values()), encoding="utf-8")


def capture(browser, url: str) -> dict:
    context = browser.new_context(user_agent=UA, viewport={"width": 1366, "height": 900}, locale="en-US",
                                  bypass_csp=True, accept_downloads=False)
    page = context.new_page()
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=45000)
        try:
            page.wait_for_load_state("networkidle", timeout=8000)
        except PlaywrightError:
            pass  # busy pages never go idle; what has rendered is enough
        page.wait_for_timeout(2000)  # let consent banners and popups appear
        page.evaluate(CONTENT_JS)
        elements = page.evaluate("window.__dpgExtract()")
        return {"url": url, "final_url": page.url, "title": page.title(),
                "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "elements": elements}
    finally:
        context.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", nargs="*", default=[], help="page ids to re-capture")
    args = ap.parse_args()

    SNAPSHOTS.mkdir(parents=True, exist_ok=True)
    pages = load_pages()
    todo = [(u, n) for u, n in read_urls()
            if page_id(u) in args.force or not (SNAPSHOTS / f"{page_id(u)}.json").exists()]
    print(f"{len(todo)} page(s) to capture")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        for url, note in todo:
            pid = page_id(url)
            try:
                snap = capture(browser, url)
            except PlaywrightError as e:
                print(f"  FAIL {pid}: {str(e).splitlines()[0][:120]}")
                continue
            (SNAPSHOTS / f"{pid}.json").write_text(json.dumps(snap, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            entry = pages.get(pid) or {"id": pid, "url": url, "snapshot": f"{pid}.json", "labels": [],
                                       "proposed_labels": [], "verified": False, "notes": note}
            pages[pid] = entry
            print(f"  ok   {pid}: {len(snap['elements'])} elements")
            save_pages(pages)
        browser.close()


if __name__ == "__main__":
    main()
