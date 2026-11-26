"""Hybrid routing, risk score, SSRF guard and API, with the LLM faked out."""
import pytest
from fastapi.testclient import TestClient

from app import classifier, llm, threat
from app.main import app
from app.schemas import PageElement, PatternType as PT, ThreatReport, ThreatSignal


HDR = {"X-DPG-Client": "test"}


def el(selector, kind="text", text="", **kw):
    return PageElement(selector=selector, kind=kind, text=text, **kw)


PAGE = [
    el("#strong", text="Only 2 left in stock"),                               # rule >= 0.8
    el("#weak", text="Limited-time collection"),                              # rule ambiguous
    el("#cue", text="12 sold in the last hour"),                              # no rule, cue word
    el("#plain", text="About us"),                                            # ignored
]


@pytest.fixture
def fake_llm(monkeypatch):
    calls = []

    def fake(elements):
        calls.append([e.selector for e in elements])
        out = {}
        for i, e in enumerate(elements):
            if e.selector == "#weak":
                out[i] = llm.LLMLabel(id=i, label="none", confidence=0.9, explanation="Just a collection name.")
            elif e.selector == "#cue":
                out[i] = llm.LLMLabel(id=i, label="fake_scarcity", confidence=0.7, explanation="High demand claim.")
        return out

    monkeypatch.setattr(llm, "classify", fake)
    return calls


def test_hybrid_only_sends_ambiguous_and_cues(fake_llm):
    findings, used, err = classifier.classify(PAGE, "hybrid")
    assert used and err is None
    assert fake_llm == [["#weak", "#cue"]]          # strong hit and plain text never reach the LLM
    by_sel = {f.element_selector: f for f in findings}
    assert by_sel["#strong"].source == "rule"
    assert "#weak" not in by_sel                     # LLM vetoed the ambiguous rule hit
    assert by_sel["#cue"].source == "llm"


def test_rules_mode_never_calls_llm(fake_llm):
    findings, used, _ = classifier.classify(PAGE, "rules")
    assert not used and fake_llm == []
    assert {f.element_selector for f in findings} == {"#strong", "#weak"}


def test_llm_failure_falls_back_to_rules(monkeypatch):
    def boom(_):
        raise llm.LLMError("connection refused")

    monkeypatch.setattr(llm, "classify", boom)
    findings, used, err = classifier.classify(PAGE, "hybrid")
    assert not used and "connection refused" in err
    assert {f.element_selector for f in findings} == {"#strong", "#weak"}


def test_risk_score():
    findings, _, _ = classifier.classify(PAGE, "rules")
    base = classifier.risk_score(findings)
    assert 0 < base <= 100
    warn = ThreatReport(url="x", signals=[ThreatSignal(name="ssl", status="bad", detail="")])
    assert classifier.risk_score(findings, warn) == base + 25
    malicious = ThreatReport(url="x", signals=[ThreatSignal(name="safe_browsing", status="bad", detail="")])
    assert classifier.risk_score([], malicious) == 100
    assert classifier.risk_score([]) == 0


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.5/",
    "http://[::1]/", "file:///etc/passwd", "ftp://example.com/", "http://example.com:22/",
])
def test_ssrf_guard_blocks(url):
    with pytest.raises(threat.UnsafeURL):
        threat.assert_public_url(url)


def test_api_analyze_rules_mode():
    client = TestClient(app)
    body = {"url": "https://shop.example/item", "mode": "rules", "include_threat": False,
            "elements": [{"selector": "#s", "kind": "text", "text": "Only 1 left in stock"}]}
    r = client.post("/analyze", json=body, headers=HDR)
    assert r.status_code == 200
    data = r.json()
    assert data["findings"][0]["pattern_type"] == PT.FAKE_SCARCITY.value
    assert set(data["findings"][0]) >= {"pattern_type", "confidence", "element_selector", "explanation"}
    assert data["risk_score"] > 0


def test_api_threat_rejects_internal_url():
    r = TestClient(app).post("/threat", json={"url": "http://169.254.169.254/"}, headers=HDR)
    assert r.status_code == 400


def test_api_requires_client_header():
    r = TestClient(app).post("/analyze", json={"url": "https://x.example/", "elements": []})
    assert r.status_code == 403


def test_drop_containers_keeps_innermost():
    els = [el("#outer", text="Deluxe room. Only 2 rooms left at this price! Book now"),
           el("#inner", text="Only 2 rooms left at this price!"),
           el("#other", text="Hurry, offer ends tonight")]
    findings, _, _ = classifier.classify(els, "rules")
    kept = classifier.drop_containers(findings, els)
    sel = {(f.element_selector, f.pattern_type.value) for f in kept}
    assert ("#inner", "fake_scarcity") in sel and ("#outer", "fake_scarcity") not in sel
    assert ("#other", "fake_urgency") in sel
