"""Build the labeled text dataset used by evaluate.py.

Positives: Mathur et al. 2019, "Dark Patterns at Scale" (GPL-3.0; downloaded, not committed).
Negatives: the "Not Dark Pattern" rows of eval/data/dark.csv (text from the same kind of shopping sites).

Each row: {"id", "text", "label" (one of our pattern types or "none"), "source", "orig_type", "split"}.
Rows whose Mathur type has no counterpart in our taxonomy are kept with label "out_of_scope"
so they can be reported separately, but they are not scored per type.

    python eval/build_dataset.py
"""
import csv
import json
import random
import urllib.request
from collections import Counter
from pathlib import Path

HERE = Path(__file__).parent
RAW = HERE / "data" / "raw"
MATHUR_URL = ("https://raw.githubusercontent.com/aruneshmathur/dark-patterns/master/"
              "data/final-dark-patterns/dark-patterns.csv")
MATHUR_CSV = RAW / "mathur_dark_patterns.csv"
KAGGLE_CSV = HERE / "data" / "dark.csv"
OUT = HERE / "data" / "text_dataset.jsonl"

SEED = 42
TEST_PER_TYPE = 80        # cap per positive type in the test split (keeps LLM runs affordable)
TEST_NEGATIVES = 320

# Mathur "Pattern Type" -> our pattern type. None = outside our taxonomy.
MATHUR_MAP = {
    "Low-stock Message": "fake_scarcity",
    "High-demand Message": "fake_scarcity",
    "Countdown Timer": "fake_urgency",
    "Limited-time Message": "fake_urgency",
    "Confirmshaming": "confirmshaming",
    "Hidden Costs": "hidden_fees",
    "Sneak into Basket": "preselected_option",
    "Forced Enrollment": "forced_consent",
    "Activity Notification": None,
    "Testimonials of Uncertain Origin": None,
    "Pressured Selling": None,
    "Visual Interference": None,
    "Trick Questions": None,
    "Hard to Cancel": None,
    "Hidden Subscription": None,
}


def clean(text: str) -> str:
    return " ".join(text.replace("�", "'").split())


def download_mathur() -> None:
    if MATHUR_CSV.exists():
        return
    RAW.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {MATHUR_URL}")
    urllib.request.urlretrieve(MATHUR_URL, MATHUR_CSV)


def load_rows() -> list[dict]:
    rows, seen = [], set()

    with open(MATHUR_CSV, encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            text = clean(r["Pattern String"])
            ptype = r["Pattern Type"].strip()
            if not text or ptype not in MATHUR_MAP:
                continue  # empty strings (mostly countdown timers recorded as screenshots)
            label = MATHUR_MAP[ptype] or "out_of_scope"
            key = (text.lower(), label)
            if key in seen:
                continue  # many pages repeat "Only 1 left"; count each string once
            seen.add(key)
            rows.append({"text": text, "label": label, "source": "mathur", "orig_type": ptype})

    with open(KAGGLE_CSV, encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            if r["Pattern Category"].strip() != "Not Dark Pattern":
                continue  # its dark rows are a relabeled copy of Mathur's; use the original instead
            text = clean(r["text"])
            key = (text.lower(), "none")
            if not text or key in seen:
                continue
            seen.add(key)
            rows.append({"text": text, "label": "none", "source": "dark.csv", "orig_type": "Not Dark Pattern"})
    return rows


def assign_split(rows: list[dict]) -> None:
    rng = random.Random(SEED)
    by_label: dict[str, list[dict]] = {}
    for r in rows:
        r["split"] = "dev"
        by_label.setdefault(r["label"], []).append(r)
    for label, items in by_label.items():
        rng.shuffle(items)
        n = TEST_NEGATIVES if label == "none" else TEST_PER_TYPE
        if label not in ("none", "out_of_scope") and len(items) < 10:
            n = len(items)  # tiny classes: everything goes to test
        for r in items[:n]:
            r["split"] = "test"


def main() -> None:
    download_mathur()
    rows = load_rows()
    assign_split(rows)
    random.Random(SEED).shuffle(rows)
    with open(OUT, "w", encoding="utf-8") as f:
        for i, r in enumerate(rows):
            f.write(json.dumps({"id": i, **r}, ensure_ascii=False) + "\n")

    counts = Counter((r["label"], r["split"]) for r in rows)
    print(f"Wrote {len(rows)} rows to {OUT}")
    for label in sorted({r["label"] for r in rows}):
        print(f"  {label:20s} test={counts[(label, 'test')]:4d}  dev={counts[(label, 'dev')]:4d}")


if __name__ == "__main__":
    main()
