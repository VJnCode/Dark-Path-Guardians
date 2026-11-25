"""Hybrid classification (rules first, LLM for ambiguous cases) and page risk score."""
import re
from typing import Optional

from . import llm
from .config import settings
from .rules import normalize, run_rules
from .schemas import Finding, Mode, PageElement, PatternType, ThreatReport

ACCEPT_THRESHOLD = 0.8   # rule findings at or above this skip the LLM
REPORT_THRESHOLD = 0.4   # nothing below this is reported
LLM_MIN_CONFIDENCE = 0.6  # LLM-only findings need at least this

# Words that make an element worth a second look even if no rule fired.
CUE_WORDS = re.compile(
    r"\b(only|left|hurry|limited|ends?|expires?|today|now|stock|demand|viewing|sold|cookies?|consent|agree"
    r"|accept|no thanks|not interested|fees?|charges?|surcharge|subscribe|newsletter|insurance|protection"
    r"|sponsored|promoted|ad|download|free trial|cancel|miss out|full price|reserved)\b")


def _is_cue(el: PageElement) -> bool:
    text = normalize(el.label or el.text)
    if el.kind in ("checkbox", "radio"):
        return bool(el.checked)
    if el.kind == "timer":
        return True
    return 3 <= len(text) <= 300 and bool(CUE_WORDS.search(text))


def _llm_finding(el: PageElement, lab: "llm.LLMLabel") -> Finding:
    return Finding(pattern_type=PatternType(lab.label), confidence=round(lab.confidence, 2),
                   element_selector=el.selector,
                   explanation=lab.explanation or "Flagged by the language model.", source="llm")


def classify(elements: list[PageElement], mode: Mode = "hybrid") -> tuple[list[Finding], bool, Optional[str]]:
    """Return (findings, llm_used, llm_error)."""
    by_selector = {}
    for el in elements:
        by_selector.setdefault(el.selector, el)

    rule_findings = [f for f in run_rules(elements) if f.confidence >= REPORT_THRESHOLD]
    if mode == "rules" or not settings.llm_enabled:
        error = None if mode == "rules" else "LLM disabled (LLM_ENABLED=false)"
        return _sorted(rule_findings), False, error

    # Pick what the LLM should look at.
    if mode == "llm":  # LLM-only baseline: the model sees every element, no rules
        accepted: list[Finding] = []
        ambiguous: list[Finding] = []
        candidates = list(elements)
    else:  # hybrid
        accepted = [f for f in rule_findings if f.confidence >= ACCEPT_THRESHOLD]
        ambiguous = [f for f in rule_findings if f.confidence < ACCEPT_THRESHOLD]
        done = {f.element_selector for f in accepted}
        amb_sel = {f.element_selector for f in ambiguous}
        candidates = [by_selector[s] for s in dict.fromkeys(f.element_selector for f in ambiguous)
                      if s in by_selector]
        candidates += [el for el in elements
                       if el.selector not in done and el.selector not in amb_sel and _is_cue(el)]

    candidates = candidates[: settings.llm_max_items]
    if not candidates:
        return _sorted(accepted + ambiguous), False, None

    try:
        labels = llm.classify(candidates)
    except llm.LLMError as e:
        # Fall back to rules: keep the ambiguous findings as they are.
        return _sorted(rule_findings), False, str(e)

    findings = list(accepted)
    ambiguous_by_sel: dict[str, list[Finding]] = {}
    for f in ambiguous:
        ambiguous_by_sel.setdefault(f.element_selector, []).append(f)

    for i, el in enumerate(candidates):
        lab = labels.get(i)
        rule_hits = ambiguous_by_sel.get(el.selector, [])
        if lab is None:              # model gave no answer: keep what the rules said
            findings.extend(rule_hits)
            continue
        if lab.label == "none":      # model says it is fine: drop ambiguous rule hits
            continue
        agreed = [f for f in rule_hits if f.pattern_type.value == lab.label]
        if agreed:
            f = agreed[0]
            findings.append(f.model_copy(update={
                "confidence": round(max(f.confidence, lab.confidence), 2), "source": "rule+llm",
                "explanation": f.explanation}))
        elif lab.confidence >= LLM_MIN_CONFIDENCE:
            findings.append(_llm_finding(el, lab))
    return _sorted(findings), True, None


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: f.confidence, reverse=True)


# ---------------------------------------------------------------- risk score

# How much each pattern type can add to the 0-100 score (at confidence 1.0).
PATTERN_WEIGHTS = {
    PatternType.HIDDEN_FEES: 20,
    PatternType.DISGUISED_AD: 20,
    PatternType.PRESELECTED_OPTION: 15,
    PatternType.FORCED_CONSENT: 15,
    PatternType.FAKE_URGENCY: 15,
    PatternType.FAKE_SCARCITY: 15,
    PatternType.CONFIRMSHAMING: 10,
}
# Points added per threat signal status.
THREAT_PENALTY = {"bad": 25, "warn": 10, "ok": 0, "unknown": 0}


def risk_score(findings: list[Finding], threat: Optional[ThreatReport] = None) -> int:
    best: dict[PatternType, float] = {}
    for f in findings:
        best[f.pattern_type] = max(best.get(f.pattern_type, 0.0), f.confidence)
    score = sum(PATTERN_WEIGHTS[pt] * conf for pt, conf in best.items())

    if threat:
        for s in threat.signals:
            if s.name == "safe_browsing" and s.status == "bad":
                return 100  # known-malicious URL: maximum risk
            score += THREAT_PENALTY[s.status]
    return int(min(100, round(score)))
