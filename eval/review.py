"""Help a human review the manual page set.

    python eval/review.py                 # condensed view of every page
    python eval/review.py booking-com     # one page, more lines
    python eval/review.py --status        # labeled / verified counts

The view lists pre-checked boxes, live timers, consent-banner buttons, fee lines and text with
pressure wording. It uses its own broad keyword list, not the detector, so reviewing doesn't
inherit the detector's blind spots. Open the snapshot JSON (or the live page) when unsure.

To label a page, edit eval/manual/pages.jsonl:
  "labels":   pattern types you confirm are present on the captured page
  "verified": true once you have checked it (only verified pages are scored)
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).parent
PAGES = HERE / "manual" / "pages.jsonl"
SNAPSHOTS = HERE / "manual" / "snapshots"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

KEYWORDS = re.compile(
    r"\b(left|stock|hurry|ends?|ending|expires?|timer|today only|limited|last chance|only \d|selling|demand"
    r"|viewing|bought|sold|claimed|reserved|cookies?|consent|accept|reject|decline|agree|no,? thanks"
    r"|not interested|fees?|charges?|surcharge|subscribe|newsletter|insurance|protection|sponsored|promoted"
    r"|advert\w*|ad|download|free trial|auto-?renew|renews?|cancel|miss out|full price|\d+% off|save \d+%)\b",
    re.I)


def condensed(elements: list[dict], limit: int) -> list[str]:
    groups = {"checked": [], "timer": [], "consent": [], "fee": [], "cue": []}
    seen = set()
    for e in elements:
        text = " ".join((e.get("label") or e.get("text") or "").split())[:110]
        if not text or text.lower() in seen:
            continue
        near = (e.get("near_text") or "").lower()
        if e["kind"] in ("checkbox", "radio") and e.get("checked"):
            groups["checked"].append(f"[x] {e['kind']}: {text}")
        elif e["kind"] == "timer":
            groups["timer"].append(f"[timer] {text}")
        elif e["kind"] in ("button", "link") and re.search(r"cookie|consent|privacy|tracking", near) and len(text) < 50:
            groups["consent"].append(f"[consent {e['kind']}] {text}")
        elif e["kind"] == "price" and re.search(r"fee|charge|surcharge", text, re.I):
            groups["fee"].append(f"[fee] {text}")
        elif KEYWORDS.search(text):
            ad = " (ad slot)" if e.get("ad_hint") else ""
            groups["cue"].append(f"[{e['kind']}{ad}] {text}")
        else:
            continue
        seen.add(text.lower())
    lines = [x for g in groups.values() for x in g]
    return lines[:limit] + ([f"... {len(lines) - limit} more"] if len(lines) > limit else [])


def main() -> None:
    pages = [json.loads(x) for x in PAGES.read_text(encoding="utf-8").splitlines() if x.strip()]
    args = sys.argv[1:]
    if args == ["--status"]:
        done = sum(p.get("verified", False) for p in pages)
        print(f"{len(pages)} pages, {done} verified, {sum(bool(p.get('proposed_labels')) for p in pages)} with proposals")
        return
    if args:
        pages = [p for p in pages if p["id"] in args]
    limit = 60 if args else 22
    for p in pages:
        snap = json.loads((SNAPSHOTS / p["snapshot"]).read_text(encoding="utf-8"))
        print(f"\n=== {p['id']}  ({len(snap['elements'])} elements)  {snap.get('title', '')[:60]}")
        print(f"    proposed={p.get('proposed_labels')}  labels={p.get('labels')}  verified={p.get('verified')}")
        for line in condensed(snap["elements"], limit):
            print("   ", line)


if __name__ == "__main__":
    main()
