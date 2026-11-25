"""Sandbox pieces that don't need Docker: hardening options, log parsing, verdicts."""
import pytest

from app import sandbox
from app.schemas import AnalyzeResponse, Finding, PatternType, ThreatReport, ThreatSignal
from app.threat import UnsafeURL
from app.verdict import decide, network_features


def test_container_is_hardened():
    opts = sandbox.container_options("abcdef123456", "https://example.com/", "pw", 0)
    assert opts["volumes"] == {} and "mounts" not in opts             # no host mounts
    assert opts["user"] == "10001:10001"                              # non-root
    assert opts["read_only"] is True
    assert opts["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in opts["security_opt"]
    assert opts["privileged"] is False
    assert opts["mem_limit"] == opts["memswap_limit"]
    assert opts["nano_cpus"] > 0 and opts["pids_limit"] > 0
    assert opts["network"] == "dpg_sandbox"
    assert "ports" not in opts                                        # nothing published to the host


def test_parse_logs():
    raw = 'noise\nDPG_REPORT {"final_url": "https://a.example/"}\nDPG_EVENT {"type": "popup"}\nDPG_EVENT {bad json\n'
    report, events = sandbox.parse_logs(raw)
    assert report == {"final_url": "https://a.example/"}
    assert events == [{"type": "popup"}]


def test_create_rejects_private_urls():
    with pytest.raises(UnsafeURL):
        sandbox.SandboxManager(client=object()).create("http://192.168.1.1/")


def test_get_requires_matching_token():
    m = sandbox.SandboxManager(client=object())
    m.sessions["abcdef123456"] = sandbox.Session(id="abcdef123456", token="right", vnc_password="x", url="u",
                                                 container_id="c", created=0, expires=0)
    assert m.get("abcdef123456", "right") is not None
    assert m.get("abcdef123456", "wrong") is None
    assert m.get("abcdef123456", "") is None
    assert m.get("../etc", "right") is None


def _analysis(score=0, findings=(), signals=()):
    return AnalyzeResponse(url="https://a.example/", risk_score=score, findings=list(findings),
                           threat=ThreatReport(url="https://a.example/", signals=list(signals)))


QUIET = {"redirect_chain": ["https://a.example/"], "request_count": 10, "failed_requests": [],
         "download_attempts": [], "popups": [], "third_party_hosts": []}


def test_clean_page_is_safe():
    v = decide(_analysis(), network_features(QUIET, "https://a.example/"))
    assert v.level == "safe"


def test_dark_patterns_make_it_suspicious():
    f = Finding(pattern_type=PatternType.FAKE_URGENCY, confidence=0.9, element_selector="#a", explanation="x")
    v = decide(_analysis(35, [f]), network_features(QUIET, "https://a.example/"))
    assert v.level == "suspicious" and any("urgency" in r.lower() for r in v.reasons)


def test_confident_dark_pattern_is_suspicious_even_with_low_score():
    f = Finding(pattern_type=PatternType.CONFIRMSHAMING, confidence=0.9, element_selector="#a", explanation="x")
    v = decide(_analysis(9, [f, f]), network_features(QUIET, "https://a.example/"))
    assert v.level == "suspicious"
    assert len(v.reasons) == len(set(v.reasons))


def test_auto_download_blocks():
    net = dict(QUIET, download_attempts=[{"url": "https://a.example/x.exe", "how": "download event"}])
    v = decide(_analysis(), network_features(net, "https://a.example/"))
    assert v.level == "block" and v.features["download_attempts"] == 1


def test_safe_browsing_hit_blocks():
    sig = ThreatSignal(name="safe_browsing", status="bad", detail="Listed as SOCIAL_ENGINEERING.")
    v = decide(_analysis(signals=[sig]), network_features(QUIET, "https://a.example/"))
    assert v.level == "block"


def test_redirect_chain_to_other_sites_adds_risk():
    net = dict(QUIET, redirect_chain=["https://a.example/", "https://t.track.example2/", "https://b.other.example3/",
                                      "https://c.final.example4/"])
    v = decide(_analysis(10), network_features(net, "https://a.example/"))
    assert v.level == "suspicious" and v.features["left_target_domain"]
