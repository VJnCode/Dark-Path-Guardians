"""Turn a sandbox run (page analysis + network log) into safe / suspicious / block."""
from urllib.parse import urlsplit

from .schemas import AnalyzeResponse, Verdict
from .threat import registered_domain

BLOCK_SCORE = 70
SUSPICIOUS_SCORE = 30


def network_features(network: dict, target_url: str) -> dict:
    """Numeric features from the sandbox's network log."""
    chain = network.get("redirect_chain", [])
    domains = {registered_domain(urlsplit(u).hostname or "") for u in chain if u}
    target = registered_domain(urlsplit(target_url).hostname or "")
    blocked_private = [f for f in network.get("failed_requests", [])
                       if "TUNNEL_CONNECTION_FAILED" in f.get("error", "") or "403" in f.get("error", "")]
    return {
        "redirects": max(0, len(chain) - 1),
        "redirect_domains": len(domains),
        "left_target_domain": bool(chain) and registered_domain(urlsplit(chain[-1]).hostname or "") != target,
        "requests": network.get("request_count", 0),
        "third_party_hosts": len(network.get("third_party_hosts", [])),
        "download_attempts": len(network.get("download_attempts", [])),
        "popups": len(network.get("popups", [])),
        "blocked_requests": len(blocked_private),
    }


def decide(analysis: AnalyzeResponse, features: dict, load_error: str | None = None) -> Verdict:
    reasons: list[str] = []
    score = analysis.risk_score
    block = False

    signals = {s.name: s for s in (analysis.threat.signals if analysis.threat else [])}
    sb = signals.get("safe_browsing")
    if sb and sb.status == "bad":
        block = True
        reasons.append(sb.detail)
    if features["download_attempts"]:
        block = True
        reasons.append(f"The page tried to start {features['download_attempts']} download(s) on its own (blocked).")
    if signals.get("redirects") and signals["redirects"].status == "bad":
        block = True
        reasons.append(signals["redirects"].detail)

    # Network behavior adds to the page's risk score.
    if features["redirects"] >= 3 or features["redirect_domains"] >= 3:
        score += 15
        reasons.append(f"{features['redirects']} redirects across {features['redirect_domains']} domains.")
    if features["left_target_domain"]:
        score += 10
        reasons.append("You end up on a different site than the link points to.")
    if features["popups"]:
        score += 10 * min(features["popups"], 3)
        reasons.append(f"The page opened {features['popups']} popup window(s).")
    if features["blocked_requests"]:
        score += 10
        reasons.append(f"{features['blocked_requests']} request(s) were refused at the sandbox's egress proxy "
                       "(private address, disallowed port, or unreachable host).")

    for name in ("domain_age", "ssl"):
        s = signals.get(name)
        if s and s.status in ("bad", "warn"):
            reasons.append(s.detail)

    for f in analysis.findings[:5]:
        reasons.append(f"{f.pattern_type.value.replace('_', ' ').capitalize()}: {f.explanation}")

    if load_error:
        reasons.append(f"The page did not load completely: {load_error}")

    score = min(100, score)
    if block or score >= BLOCK_SCORE:
        level = "block"
    elif (score >= SUSPICIOUS_SCORE or any(s.status == "bad" for s in signals.values())
          or any(f.confidence >= 0.8 for f in analysis.findings)):  # confirmed manipulative UI
        level = "suspicious"
    else:
        level = "safe"
    reasons = list(dict.fromkeys(reasons))  # the same message can come from several elements
    if not reasons:
        reasons.append("No dark patterns or threat signals found.")
    return Verdict(level=level, score=score, reasons=reasons, features=features)
