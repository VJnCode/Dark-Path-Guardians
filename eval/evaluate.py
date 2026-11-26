"""Precision / recall / F1 per pattern type for rules-only vs LLM-only vs hybrid.

    python eval/build_dataset.py                       # once
    python eval/evaluate.py --mode all                 # writes eval/results.md and updates the README
    python eval/evaluate.py --mode rules --split all   # rules on every row (fast)
    python eval/evaluate.py --mode all --reuse         # re-render from saved predictions

Two test sets:
  * text set  - single UI strings (Mathur et al. positives + dark.csv negatives), scored per string.
  * page set  - eval/manual/pages.jsonl, captured pages scored per page (pattern present or not).
                Only rows with "verified": true are scored.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent
TEXT_DATA = HERE / "data" / "text_dataset.jsonl"
PAGES = HERE / "manual" / "pages.jsonl"
SNAPSHOTS = HERE / "manual" / "snapshots"
OUT_DIR = HERE / "out"
RESULTS = HERE / "results.md"
README = ROOT / "README.md"
CHUNK = 20  # strings per pseudo-page sent through the classifier
MIN_SUPPORT = 10  # types with fewer test rows are shown but left out of the macro average

TYPES = ["fake_urgency", "fake_scarcity", "preselected_option", "hidden_fees",
         "confirmshaming", "forced_consent", "disguised_ad"]
MODES = ["rules", "llm", "hybrid"]


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=MODES + ["all"], default="all")
    p.add_argument("--split", choices=["test", "dev", "all"], default="test")
    p.add_argument("--model", help="override LLM_MODEL")
    p.add_argument("--base-url", help="override LLM_BASE_URL (default http://localhost:11434/v1)")
    p.add_argument("--reuse", action="store_true", help="use saved predictions instead of re-running")
    p.add_argument("--no-readme", action="store_true", help="don't update the README metrics block")
    return p.parse_args()


ARGS = parse_args()
sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to cp1252
if ARGS.model:
    os.environ["LLM_MODEL"] = ARGS.model
if ARGS.base_url:
    os.environ["LLM_BASE_URL"] = ARGS.base_url
os.environ.setdefault("LLM_TIMEOUT_S", "300")
sys.path.insert(0, str(ROOT / "backend"))

from app.classifier import classify  # noqa: E402  (needs the env vars above)
from app.config import settings  # noqa: E402
from app.schemas import PageElement  # noqa: E402


# ---------------------------------------------------------------- running the classifier

def string_to_element(row: dict) -> PageElement:
    # The datasets don't say what kind of element a string came from. Use one label-blind rule
    # for every row: short strings are treated as buttons, longer ones as text.
    kind = "button" if len(row["text"]) <= 80 else "text"
    return PageElement(selector=f"#r{row['id']}", kind=kind, text=row["text"][:1000])


def predict_text(rows: list[dict], mode: str) -> tuple[dict[int, list[str]], dict]:
    preds: dict[int, list[str]] = {}
    errors = 0
    start = time.time()
    # Rules run per string so page-level rules can't mix unrelated strings.
    chunk = 1 if mode == "rules" else CHUNK
    for i in range(0, len(rows), chunk):
        batch = rows[i:i + chunk]
        findings, _, err = classify([string_to_element(r) for r in batch], mode)
        if err:
            errors += 1
        for r in batch:
            sel = f"#r{r['id']}"
            preds[r["id"]] = sorted({f.pattern_type.value for f in findings if f.element_selector == sel})
        if mode != "rules":
            print(f"  {mode}: {min(i + chunk, len(rows))}/{len(rows)}", end="\r", flush=True)
    if mode != "rules":
        print()
    return preds, {"seconds": round(time.time() - start, 1), "llm_errors": errors, "batches": -(-len(rows) // chunk)}


def predict_pages(pages: list[dict], mode: str) -> tuple[dict[str, list[str]], dict]:
    preds, errors, start = {}, 0, time.time()
    for p in pages:
        snap = json.loads((SNAPSHOTS / p["snapshot"]).read_text(encoding="utf-8"))
        elements = [PageElement(**e) for e in snap["elements"]]
        findings, _, err = classify(elements, mode)
        errors += bool(err)
        preds[p["id"]] = sorted({f.pattern_type.value for f in findings})
    return preds, {"seconds": round(time.time() - start, 1), "llm_errors": errors, "batches": len(pages)}


# ---------------------------------------------------------------- metrics

def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def score(gold: dict, pred: dict) -> dict:
    """gold/pred: id -> set of pattern types. Returns per-type and summary metrics."""
    out = {"types": {}}
    for t in TYPES:
        tp = sum(1 for k, g in gold.items() if t in g and t in pred.get(k, ()))
        fp = sum(1 for k, g in gold.items() if t not in g and t in pred.get(k, ()))
        fn = sum(1 for k, g in gold.items() if t in g and t not in pred.get(k, ()))
        support = sum(1 for g in gold.values() if t in g)
        out["types"][t] = {"support": support, "prf": prf(tp, fp, fn), "fp": fp}
    scored = [m["prf"] for m in out["types"].values() if m["support"] >= MIN_SUPPORT]
    out["macro"] = tuple(sum(x[i] for x in scored) / len(scored) for i in range(3)) if scored else (0, 0, 0)
    # Binary: is this a dark pattern at all (any type)?
    tp = sum(1 for k, g in gold.items() if g and pred.get(k))
    fp = sum(1 for k, g in gold.items() if not g and pred.get(k))
    fn = sum(1 for k, g in gold.items() if g and not pred.get(k))
    out["any"] = prf(tp, fp, fn)
    return out


# ---------------------------------------------------------------- report

def fmt(x: float) -> str:
    return f"{x:.2f}"


def table(title: str, results: dict, note: str = "") -> list[str]:
    modes = [m for m in MODES if m in results]
    lines = [f"#### {title}", ""]
    if note:
        lines += [note, ""]
    head = "| Pattern | n | " + " | ".join(f"{m.capitalize()} P | R | F1" for m in modes) + " |"
    lines += [head, "|" + "---|" * (2 + 3 * len(modes))]
    any_mode = results[modes[0]]["metrics"]
    for t in TYPES:
        n = any_mode["types"][t]["support"]
        if n == 0 and all(results[m]["metrics"]["types"][t]["fp"] == 0 for m in modes):
            continue
        cells = []
        for m in modes:
            p, r, f = results[m]["metrics"]["types"][t]["prf"]
            cells += [fmt(p), fmt(r), fmt(f)] if n else [f"({results[m]['metrics']['types'][t]['fp']} FP)", "–", "–"]
        small = "*" if 0 < n < MIN_SUPPORT else ""
        lines.append(f"| {t}{small} | {n} | " + " | ".join(cells) + " |")
    for label, key in [("**Macro avg**", "macro"), ("**Any dark pattern**", "any")]:
        cells = [fmt(v) for m in modes for v in results[m]["metrics"][key]]
        lines.append(f"| {label} | | " + " | ".join(cells) + " |")
    timing = " · ".join(f"{m}: {results[m]['stats']['seconds']}s"
                        + (f", {results[m]['stats']['llm_errors']} LLM errors" if results[m]['stats']['llm_errors'] else "")
                        for m in modes)
    lines += ["", f"Run time: {timing}.", ""]
    return lines


def render(text_results: dict, page_results: dict, text_info: dict, page_info: dict) -> str:
    lines = [f"Model: `{settings.llm_model}` (local, via Ollama) · split: `{ARGS.split}` · "
             f"generated {time.strftime('%Y-%m-%d')}", ""]
    if text_results:
        lines += table(
            "Text set (Mathur et al. 2019 + dark.csv negatives)", text_results,
            f"{text_info['n']} strings ({text_info['neg']} negatives). Macro average covers types with "
            f"n ≥ {MIN_SUPPORT}; * marks types with too few examples to trust. "
            f"{text_info['oos_n']} out-of-scope dark strings (e.g. activity notifications) are excluded; "
            "share of them flagged as some pattern: "
            + ", ".join(f"{m} {text_results[m]['oos_rate']:.0%}" for m in MODES if m in text_results) + ".")
    if page_results:
        lines += table("Manual page set (per page)", page_results,
                       f"{page_info['verified']} verified pages out of {page_info['total']}.")
    else:
        lines += ["#### Manual page set (per page)", "",
                  f"Pending review: {page_info['verified']} of {page_info['total']} pages verified. "
                  "See `eval/manual/README.md`.", ""]
    return "\n".join(lines)


def update_readme(md: str) -> None:
    start, end = "<!-- METRICS:START -->", "<!-- METRICS:END -->"
    if not README.exists():
        return
    text = README.read_text(encoding="utf-8")
    if start in text and end in text:
        before, rest = text.split(start, 1)
        after = rest.split(end, 1)[1]
        README.write_text(f"{before}{start}\n{md}\n{end}{after}", encoding="utf-8")
        print("Updated README metrics block.")


# ---------------------------------------------------------------- main

def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_or_load(name: str, mode: str, fn, items):
    OUT_DIR.mkdir(exist_ok=True)
    path = OUT_DIR / f"pred_{name}_{mode}_{ARGS.split}.json"
    if ARGS.reuse and path.exists():
        saved = json.loads(path.read_text(encoding="utf-8"))
        return {k if name == "pages" else int(k): v for k, v in saved["preds"].items()}, saved["stats"]
    print(f"Running {mode} on {len(items)} {name} items...")
    preds, stats = fn(items, mode)
    path.write_text(json.dumps({"model": settings.llm_model, "stats": stats, "preds": preds}), encoding="utf-8")
    return preds, stats


def main() -> None:
    modes = MODES if ARGS.mode == "all" else [ARGS.mode]

    rows = load_jsonl(TEXT_DATA)
    if not rows:
        sys.exit("No dataset. Run: python eval/build_dataset.py")
    if ARGS.split != "all":
        rows = [r for r in rows if r["split"] == ARGS.split]
    in_scope = [r for r in rows if r["label"] != "out_of_scope"]
    oos = [r for r in rows if r["label"] == "out_of_scope"]
    gold_text = {r["id"]: ({r["label"]} if r["label"] != "none" else set()) for r in in_scope}

    pages = load_jsonl(PAGES)
    verified = [p for p in pages if p.get("verified")]
    gold_pages = {p["id"]: set(p["labels"]) for p in verified}

    text_results, page_results = {}, {}
    for mode in modes:
        preds, stats = run_or_load("text", mode, predict_text, in_scope + oos)
        preds_sets = {k: set(v) for k, v in preds.items()}
        text_results[mode] = {
            "metrics": score(gold_text, preds_sets), "stats": stats,
            "oos_rate": (sum(1 for r in oos if preds_sets.get(r["id"])) / len(oos)) if oos else 0.0,
        }
        if verified:
            ppreds, pstats = run_or_load("pages", mode, predict_pages, verified)
            page_results[mode] = {"metrics": score(gold_pages, {k: set(v) for k, v in ppreds.items()}),
                                  "stats": pstats}

    md = render(text_results, page_results,
                {"n": len(in_scope), "neg": sum(1 for r in in_scope if r["label"] == "none"), "oos_n": len(oos)},
                {"verified": len(verified), "total": len(pages)})
    RESULTS.write_text("## Detection metrics\n\n" + md + "\n", encoding="utf-8")
    print("\n" + md)
    print(f"Wrote {RESULTS}")
    if not ARGS.no_readme and ARGS.mode == "all":
        update_readme(md)


if __name__ == "__main__":
    main()
