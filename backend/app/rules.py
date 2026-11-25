"""Rule-based dark pattern checks.

Each check is a plain function that looks at extracted page elements and
returns Findings. Confidence levels follow one convention:

    >= 0.8      strong, accepted without the LLM
    0.4 - 0.8   ambiguous, sent to the LLM in hybrid mode
"""
import re
from typing import Iterable, Optional

from .schemas import Finding, PageElement, PatternType

STRONG = 0.85
WEAK = 0.6
AMBIGUOUS = 0.45


def normalize(text: str) -> str:
    text = text.replace("’", "'").replace("‘", "'").replace(" ", " ")
    return re.sub(r"\s+", " ", text).strip().lower()


def _any(patterns: Iterable[str], text: str) -> Optional[re.Match]:
    for p in patterns:
        m = re.search(p, text)
        if m:
            return m
    return None


def _finding(pt: PatternType, conf: float, el: PageElement, why: str) -> Finding:
    return Finding(pattern_type=pt, confidence=conf, element_selector=el.selector,
                   explanation=why, source="rule")


# ---------------------------------------------------------------- urgency

URGENCY_STRONG = [
    r"\b(offer|sale|deal|discount|price|promo(tion)?|coupon)s? (ends|expires|ending)\b",
    r"\b(ends?|expires?|ending) in:? ?\d",
    r"\b(only|just) \d+ ?(hours?|hrs?|minutes?|mins?) (left|remaining)\b",
    r"\b(today|tonight) only\b",
    r"\bonly today\b",
    r"\blast chance\b",
    r"\bhurry\b",
    r"\bact (now|fast)\b",
    r"\b(ends|ending) (tonight|today|soon|at midnight)\b",
    r"\b(reserved|held) for (you for )?(the next )?\d+ ?(minutes?|mins?)\b",
]
URGENCY_WEAK = [
    r"\blimited[- ]time\b",
    r"\bdon't miss( out)?\b",
    r"\bwhile (supplies|stocks?) lasts?\b",
    r"\bflash sale\b",
    r"\bnow or never\b",
    r"\btime is running out\b",
]
URGENCY_CONTEXT = r"\b(sale|offer|deal|discount|ends?|left|expires?|reserved|held|hurry|order (within|in)|delivery)\b"


def check_urgency(el: PageElement) -> list[Finding]:
    text = normalize(el.text)
    if el.kind == "timer" and el.changing:
        if re.search(URGENCY_CONTEXT, normalize(el.text + " " + el.near_text)):
            return [_finding(PatternType.FAKE_URGENCY, 0.9, el,
                             "Live countdown timer attached to an offer pressures you to decide quickly.")]
        return [_finding(PatternType.FAKE_URGENCY, WEAK, el,
                         "Live countdown timer; unclear what it counts down to.")]
    m = _any(URGENCY_STRONG, text)
    if m:
        return [_finding(PatternType.FAKE_URGENCY, STRONG, el,
                         f"Urgency message ('{m.group(0)}') pushes you to act before you can compare.")]
    m = _any(URGENCY_WEAK, text)
    if m:
        return [_finding(PatternType.FAKE_URGENCY, WEAK, el,
                         f"Possible artificial urgency ('{m.group(0)}').")]
    return []


# ---------------------------------------------------------------- scarcity

SCARCITY_STRONG = [
    r"\b(only|just) \d+ (left|remaining)\b",
    r"\b(only|just) \d+ (items?|units?|pieces?|rooms?|seats?|tickets?|copies|spots?) (left|remaining)\b",
    r"\bonly \d+ (left )?in stock\b",
    r"\b\d+ (people|others|shoppers|customers|users|travell?ers|guests) (are )?"
    r"(viewing|looking at|watching|have this in their (cart|basket|bag))\b",
    r"\b(last|final) (one|item|room|seat|ticket)s? (left|available)\b",
    r"\b(almost|nearly) (gone|sold out)\b",
]
SCARCITY_WEAK = [
    r"\b(low|limited) (stock|quantity|availability|supply)\b",
    r"\bselling fast\b",
    r"\bgoing fast\b",
    r"\b(in )?high demand\b",
]


def check_scarcity(el: PageElement) -> list[Finding]:
    text = normalize(el.text)
    m = _any(SCARCITY_STRONG, text)
    if m:
        return [_finding(PatternType.FAKE_SCARCITY, STRONG, el,
                         f"Scarcity claim ('{m.group(0)}') suggests you might miss out.")]
    m = _any(SCARCITY_WEAK, text)
    if m:
        return [_finding(PatternType.FAKE_SCARCITY, WEAK, el,
                         f"Possible scarcity pressure ('{m.group(0)}').")]
    return []


# ---------------------------------------------------------------- pre-checked boxes

OPT_IN = (
    r"\b(newsletters?|subscribe|subscription|marketing|promotions?|promotional|special offers|offers|deals"
    r"|updates|email me|send me|text me|sms|partners?|third[- ]part(y|ies)|share my|insurance"
    r"|protection( plan)?|warranty|donat(e|ion)|round up|gift wrap|priority|express|upgrade|carbon offset"
    r"|tip|add (it |this )?to (my )?(order|cart|basket))\b"
)
HARMLESS_CHECKED = r"\b(remember me|keep me (signed|logged) in|same as (shipping|billing)|stay signed in)\b"
PAID_ADDON = r"\b(insurance|protection|warranty|premium|donat(e|ion)|tip|upgrade|priority)\b"


def check_preselected(el: PageElement) -> list[Finding]:
    if el.kind not in ("checkbox", "radio") or not el.checked:
        return []
    label = normalize(el.label or el.text)
    if re.search(HARMLESS_CHECKED, label):
        return []
    if el.kind == "radio":
        if re.search(PAID_ADDON, label):
            return [_finding(PatternType.PRESELECTED_OPTION, 0.75, el,
                             f"A paid add-on is selected by default ('{label[:80]}').")]
        return []
    if re.search(OPT_IN, label):
        shown = (el.label or el.text).strip()[:80]
        return [_finding(PatternType.PRESELECTED_OPTION, 0.9, el,
                         f"Box '{shown}' is pre-checked, so you are opted in unless you notice and untick it.")]
    return [_finding(PatternType.PRESELECTED_OPTION, AMBIGUOUS, el,
                     "Box is pre-checked; it may add something you did not choose.")]


# ---------------------------------------------------------------- hidden fees

FEE_LINE = (r"\b(service|handling|processing|convenience|booking|admin(istration)?|platform|resort|cleaning"
            r"|facility|small order|transaction|payment|reservation)\s+(fee|charge)s?\b|\bsurcharge\b")
FEE_DISCLAIMER = (r"(\+|plus) (taxes and )?fees\b|\bfees (not|are not) included\b|\bexcl(\.|uding|udes)? "
                  r"(taxes (and|&) )?fees\b|\bfees may apply\b|\badditional fees\b")
_AMOUNT = re.compile(r"(?:[$€£₹¥]|usd|eur|gbp|inr|rs\.?)\s?(\d[\d,]*(?:\.\d{1,2})?)|(\d[\d,]*(?:\.\d{1,2})?)\s?(?:€|eur|usd)")


def parse_amount(text: str) -> Optional[float]:
    m = _AMOUNT.search(normalize(text))
    if not m:
        return None
    raw = (m.group(1) or m.group(2)).replace(",", "")
    try:
        return float(raw)
    except ValueError:
        return None


def check_fee_line(el: PageElement) -> list[Finding]:
    text = normalize(el.text)
    m = re.search(FEE_LINE, text)
    if m:
        conf = 0.7 if (el.kind == "price" or parse_amount(text) is not None) else 0.5
        return [_finding(PatternType.HIDDEN_FEES, conf, el,
                         f"Extra '{m.group(0)}' added on top of the advertised price.")]
    m = re.search(FEE_DISCLAIMER, text)
    if m:
        return [_finding(PatternType.HIDDEN_FEES, 0.75, el,
                         f"Price shown excludes fees ('{m.group(0)}'), so the real cost is higher.")]
    return []


def check_total_mismatch(elements: list[PageElement]) -> list[Finding]:
    """Flag a total that is larger than subtotal + every listed charge."""
    subtotal = total = None
    total_el = None
    adjustments = 0.0
    for el in elements:
        if el.kind not in ("price", "text"):
            continue
        text = normalize(el.text)
        amount = parse_amount(text)
        if amount is None:
            continue
        if re.search(r"\bsub-?total\b", text):
            subtotal = amount
        elif re.search(r"\b(order |grand )?total\b", text):
            total, total_el = amount, el
        elif re.search(r"\b(discount|savings|coupon|promo)\b", text):
            adjustments -= amount
        elif re.search(r"\b(shipping|delivery|tax|vat|gst|fee|charge|surcharge)\b", text):
            adjustments += amount
    if subtotal is None or total is None or total_el is None:
        return []
    gap = total - (subtotal + adjustments)
    if gap > 0.5:
        return [_finding(PatternType.HIDDEN_FEES, 0.8, total_el,
                         f"Total is {gap:.2f} more than the subtotal plus the charges shown; "
                         "something was added without being listed.")]
    return []


# ---------------------------------------------------------------- confirmshaming

DECLINE_LEAD = (r"^(no|nope|nah|i'll pass|skip|maybe later|not now)\b"
                r"|\bi (don't|do not|am not|prefer not|would rather)\b|\bi'(m not|d rather)\b|\bi'm (fine|ok|okay)\b")
SHAMING = [
    r"\b(want|like|need|care about|interested in)( to)? (sav|discount|deal|free|money|lower|better|protect|secur"
    r"|learn|improv|health|fit|smart|success|grow|exclusive|offer|perk|reward|win)",
    r"\bfull price\b", r"\bpay(ing)? (full|more)\b", r"\bmiss(ing)? out\b",
    r"\bstay(ing)? (uninformed|ignorant|behind|broke)\b", r"\blike (losing|wasting|paying)\b",
    r"\bhate (sav|money|deal|free)", r"\b(rather|prefer to) (pay|miss|lose|stay)\b",
    r"\b(fine|ok|okay) (with )?(missing|paying|losing)\b", r"\bunprotected\b",
]


def check_confirmshaming(el: PageElement) -> list[Finding]:
    if el.kind not in ("button", "link"):
        return []
    text = normalize(el.text)
    if not text or len(text) > 150:
        return []
    lead = re.search(DECLINE_LEAD, text)
    shame = _any(SHAMING, text)
    if lead and shame:
        return [_finding(PatternType.CONFIRMSHAMING, 0.9, el,
                         f"The decline option ('{el.text.strip()[:80]}') is worded to make you feel bad for saying no.")]
    if lead and re.search(r"\bi (don't|do not) (want|like|need|care)\b", text):
        return [_finding(PatternType.CONFIRMSHAMING, 0.5, el,
                         "Decline option uses a guilt-laden first-person statement.")]
    return []


# ---------------------------------------------------------------- forced consent

COOKIE_CONTEXT = r"\b(cookies?|consent|tracking|privacy|personal data|gdpr|personali[sz]ed ads?)\b"
IMPLIED_CONSENT = (r"\bby (continuing|using|browsing|staying|scrolling)\b.{0,80}\b(agree|accept|consent)\b"
                   r"|\bcontinued use of (this|the|our) (site|website)\b.{0,60}\b(accept|agree|consent)")
ACCEPT_BTN = (r"^(accept( all)?( cookies)?|agree( and (close|continue))?|i agree|allow( all)?( cookies)?|got it"
              r"|ok(ay)?|i understand|continue|yes,? i (agree|accept)|consent)\b")
REJECT_BTN = (r"\b(reject|decline|deny|refuse|disagree|opt[- ]out|necessary only|only necessary|essential only"
              r"|only essential|strictly necessary|do not (sell|accept)|continue without accepting)\b")


def check_forced_consent(elements: list[PageElement]) -> list[Finding]:
    findings: list[Finding] = []
    accepts, rejects = [], []
    for el in elements:
        if el.kind not in ("button", "link"):
            continue
        text = normalize(el.text)
        if not text or len(text) > 50:
            continue
        in_consent_ui = bool(re.search(COOKIE_CONTEXT, normalize(el.near_text)))
        if not in_consent_ui:
            continue
        if re.search(REJECT_BTN, text):
            rejects.append(el)
        elif re.search(ACCEPT_BTN, text):
            accepts.append(el)

    if accepts and not rejects:
        findings.append(_finding(PatternType.FORCED_CONSENT, 0.8, accepts[0],
                                 "Consent prompt offers 'Accept' but no equally easy way to reject."))
    elif accepts and rejects:
        accept_is_button = any(a.kind == "button" for a in accepts)
        rejects_are_links = all(r.kind == "link" for r in rejects)
        if accept_is_button and rejects_are_links:
            findings.append(_finding(PatternType.FORCED_CONSENT, 0.55, rejects[0],
                                     "Reject is a small link while Accept is a prominent button."))

    for el in elements:
        if el.kind in ("text", "banner") and re.search(IMPLIED_CONSENT, normalize(el.text)):
            findings.append(_finding(PatternType.FORCED_CONSENT, 0.7, el,
                                     "Implied consent: just using the site is treated as agreement."))
            break
    return findings


# ---------------------------------------------------------------- disguised ads

AD_NETWORKS = (r"(doubleclick\.net|googlesyndication\.com|googleadservices\.com|adservice\.google|taboola\.com"
               r"|outbrain\.com|adnxs\.com|criteo\.(com|net)|amazon-adsystem\.com|popads\.net|propellerads"
               r"|adsterra|mgid\.com|revcontent\.com)")
CONTROL_TEXT = (r"^(free )?(download|start|play|continue|next|get( it)?|install|watch|click here|open|proceed"
                r"|skip ad|close)( now| download| here)?\b")
AD_DISCLOSURE = r"\b(sponsored|promoted|paid (content|post|partnership)|advertisement|advertorial)\b"


def check_disguised_ad(el: PageElement) -> list[Finding]:
    if el.kind not in ("button", "link", "text"):
        return []
    text = normalize(el.text)
    is_ad = el.ad_hint or bool(re.search(AD_NETWORKS, el.href.lower()))
    if el.kind in ("button", "link") and is_ad and len(text) <= 40 and re.search(CONTROL_TEXT, text):
        return [_finding(PatternType.DISGUISED_AD, STRONG, el,
                         f"'{el.text.strip()[:40]}' looks like a site control but is an ad.")]
    if el.kind in ("link", "text") and len(text) > 30 and re.search(AD_DISCLOSURE, normalize(el.near_text)):
        return [_finding(PatternType.DISGUISED_AD, 0.5, el,
                         "Sponsored item styled like regular content.")]
    return []


# ---------------------------------------------------------------- runner

ELEMENT_RULES = [check_urgency, check_scarcity, check_preselected, check_fee_line,
                 check_confirmshaming, check_disguised_ad]
PAGE_RULES = [check_total_mismatch, check_forced_consent]


def run_rules(elements: list[PageElement]) -> list[Finding]:
    """Run every rule; keep the highest-confidence finding per (element, pattern)."""
    best: dict[tuple[str, PatternType], Finding] = {}
    raw: list[Finding] = []
    for el in elements:
        for rule in ELEMENT_RULES:
            raw.extend(rule(el))
    for rule in PAGE_RULES:
        raw.extend(rule(elements))
    for f in raw:
        key = (f.element_selector, f.pattern_type)
        if key not in best or f.confidence > best[key].confidence:
            best[key] = f
    return list(best.values())
