"""Unit tests for the rule engine: one positive and one negative set per pattern."""
import pytest

from app import rules
from app.schemas import PageElement, PatternType as PT


def el(kind="text", text="", **kw) -> PageElement:
    return PageElement(selector=kw.pop("selector", "#x"), kind=kind, text=text, **kw)


def types(findings, min_conf=0.0):
    return {f.pattern_type for f in findings if f.confidence >= min_conf}


# ---------------------------------------------------------------- urgency

@pytest.mark.parametrize("text", [
    "Sale ends in 02:14:55", "Offer expires tonight", "Hurry! Prices go up soon",
    "Today only: 40% off", "Last chance to get this deal", "Your seat is reserved for 10 minutes",
])
def test_urgency_positive(text):
    assert PT.FAKE_URGENCY in types(rules.check_urgency(el(text=text)), 0.8)


@pytest.mark.parametrize("text", ["Free returns within 30 days", "Ends of the earth travel guide", "Order history"])
def test_urgency_negative(text):
    assert rules.check_urgency(el(text=text)) == []


def test_urgency_weak_is_ambiguous():
    f = rules.check_urgency(el(text="Limited-time collection"))
    assert f and 0.4 <= f[0].confidence < 0.8


def test_live_timer_next_to_offer():
    f = rules.check_urgency(el(kind="timer", text="09:59", changing=True, near_text="Deal ends in 09:59"))
    assert f[0].confidence >= 0.8


def test_static_time_is_not_timer():
    assert rules.check_urgency(el(kind="timer", text="10:30", changing=False)) == []


@pytest.mark.parametrize("text", [
    "Your cart is reserved for 09:57 minutes!", "00Days17Hours12Mins13Secs", "Order within 0:02:41",
    "Time remaining: 04:50", "60% OFF ENDS IN DAYS HOURS MINUTES SECONDS",
])
def test_countdown_text(text):
    assert PT.FAKE_URGENCY in types(rules.check_urgency(el(text=text)), 0.8)


def test_hurry_with_stock_claim_is_scarcity_only():
    f = rules.run_rules([el(text="Hurry! Only 2 left in stock")])
    assert types(f) == {PT.FAKE_SCARCITY}


def test_hurry_alone_is_urgency():
    assert PT.FAKE_URGENCY in types(rules.check_urgency(el(text="Hurry, act now!")), 0.8)


# ---------------------------------------------------------------- scarcity

@pytest.mark.parametrize("text", [
    "Only 2 left in stock", "Just 3 rooms left", "14 people are viewing this right now",
    "Almost gone!", "Last ticket available",
])
def test_scarcity_positive(text):
    assert PT.FAKE_SCARCITY in types(rules.check_scarcity(el(text=text)), 0.8)


@pytest.mark.parametrize("text", ["1 LEFT", "20 units left", "74% offers claimed. Hurry up!",
                                  "Only 5 pcs left!", "Less than 10 left!"])
def test_scarcity_loose_phrasing(text):
    assert PT.FAKE_SCARCITY in types(rules.check_scarcity(el(text=text)), 0.8)


@pytest.mark.parametrize("text", ["In stock", "Ships in 2 days", "2 left turns then straight",
                                  "Movies on demand", "Characters remaining: 200"])
def test_scarcity_negative(text):
    assert rules.check_scarcity(el(text=text)) == []


# ---------------------------------------------------------------- pre-checked boxes

def test_prechecked_newsletter():
    f = rules.check_preselected(el(kind="checkbox", checked=True, label="Yes, send me marketing emails"))
    assert f[0].pattern_type == PT.PRESELECTED_OPTION and f[0].confidence >= 0.8


def test_prechecked_insurance_radio():
    f = rules.check_preselected(el(kind="radio", checked=True, label="Add travel insurance (+$19)"))
    assert f and f[0].confidence >= 0.7


@pytest.mark.parametrize("kw", [
    dict(kind="checkbox", checked=False, label="Subscribe to our newsletter"),  # not checked
    dict(kind="checkbox", checked=True, label="Remember me"),                   # harmless
    dict(kind="radio", checked=True, label="Standard shipping"),                # normal choice
])
def test_prechecked_negative(kw):
    assert rules.check_preselected(el(**kw)) == []


def test_prechecked_unknown_label_is_ambiguous():
    f = rules.check_preselected(el(kind="checkbox", checked=True, label="Option A"))
    assert f and f[0].confidence < 0.8


# ---------------------------------------------------------------- hidden fees

@pytest.mark.parametrize("text", ["Service fee $4.99", "Booking fee: £12", "Prices + fees", "Excludes taxes and fees"])
def test_fee_line_positive(text):
    assert PT.HIDDEN_FEES in types(rules.check_fee_line(el(kind="price", text=text)))


@pytest.mark.parametrize("text", ["$19.99", "Free shipping on orders over $50", "Fee-free returns"])
def test_fee_line_negative(text):
    assert rules.check_fee_line(el(kind="price", text=text)) == []


def test_total_mismatch():
    page = [
        el(kind="price", text="Subtotal $50.00", selector="#sub"),
        el(kind="price", text="Shipping $5.00", selector="#ship"),
        el(kind="price", text="Total $62.50", selector="#total"),
    ]
    f = rules.check_total_mismatch(page)
    assert f and f[0].element_selector == "#total" and f[0].confidence >= 0.8


def test_total_matches():
    page = [
        el(kind="price", text="Subtotal $50.00"), el(kind="price", text="Tax $4.00"),
        el(kind="price", text="Discount $10.00"), el(kind="price", text="Total $44.00"),
    ]
    assert rules.check_total_mismatch(page) == []


def test_parse_amount():
    assert rules.parse_amount("Total: $1,234.50") == 1234.50
    assert rules.parse_amount("19,99 € incl. VAT") is not None
    assert rules.parse_amount("no price here") is None


# ---------------------------------------------------------------- confirmshaming

@pytest.mark.parametrize("text", [
    "No thanks, I prefer paying full price", "No, I don't want to save money",
    "I'd rather miss out on great deals", "Nope, I like staying uninformed",
])
def test_confirmshaming_positive(text):
    assert PT.CONFIRMSHAMING in types(rules.check_confirmshaming(el(kind="button", text=text)), 0.8)


@pytest.mark.parametrize("text", ["No thanks", "Close", "Maybe later", "Continue to checkout"])
def test_confirmshaming_negative(text):
    assert rules.check_confirmshaming(el(kind="button", text=text)) == []


def test_confirmshaming_ignores_body_text():
    assert rules.check_confirmshaming(el(kind="text", text="No thanks, I prefer paying full price")) == []


# ---------------------------------------------------------------- forced consent

COOKIE = "We use cookies to personalise ads and analyse traffic."


def test_accept_without_reject():
    page = [el(kind="button", text="Accept all", near_text=COOKIE, selector="#ok"),
            el(kind="button", text="Settings", near_text=COOKIE, selector="#set")]
    f = rules.check_forced_consent(page)
    assert f and f[0].element_selector == "#ok" and f[0].confidence >= 0.8


def test_accept_and_reject_buttons_ok():
    page = [el(kind="button", text="Accept all", near_text=COOKIE),
            el(kind="button", text="Reject all", near_text=COOKIE, selector="#no")]
    assert rules.check_forced_consent(page) == []


def test_reject_hidden_as_link_is_ambiguous():
    page = [el(kind="button", text="Accept", near_text=COOKIE),
            el(kind="link", text="Continue without accepting", near_text=COOKIE, selector="#no")]
    f = rules.check_forced_consent(page)
    assert f and f[0].confidence < 0.8


def test_implied_consent_text():
    f = rules.check_forced_consent([el(text="By continuing to browse this site you agree to our use of cookies.")])
    assert f and f[0].pattern_type == PT.FORCED_CONSENT


def test_banner_buttons_far_from_banner_text():
    page = [el(kind="banner", text="This site uses cookies and related technologies for analytics and ads."),
            el(kind="button", text="Manage Settings", near_text="Manage Settings Agree"),
            el(kind="button", text="Agree", near_text="Manage Settings Agree", selector="#agree")]
    f = rules.check_forced_consent(page)
    assert f and f[0].element_selector == "#agree"


def test_strict_labels_need_a_cookie_notice():
    assert rules.check_forced_consent([el(kind="button", text="Agree", near_text="Rate this article")]) == []


def test_terms_notice_is_not_cookie_consent():
    assert rules.check_forced_consent([el(text="By continuing past this page, you agree to our terms of use")]) == []


def test_link_starting_with_consent_is_not_a_button():
    page = [el(kind="link", text="Consent interfaces", near_text="Patterns: cookies and consent")]
    assert rules.check_forced_consent(page) == []


def test_privacy_footer_is_not_consent_ui():
    page = [el(kind="button", text="Continue", near_text="Terms of Use | Privacy Policy | Sitemap")]
    assert rules.check_forced_consent(page) == []


def test_accept_outside_consent_ui_ignored():
    assert rules.check_forced_consent([el(kind="button", text="Continue", near_text="Shipping address")]) == []


# ---------------------------------------------------------------- disguised ads

def test_fake_download_button():
    f = rules.check_disguised_ad(el(kind="link", text="Download Now",
                                    href="https://ad.doubleclick.net/click?x=1"))
    assert f and f[0].confidence >= 0.8


def test_ad_slot_with_control_text():
    assert rules.check_disguised_ad(el(kind="button", text="Start", ad_hint=True))


def test_real_download_button():
    assert rules.check_disguised_ad(el(kind="link", text="Download", href="https://example.org/file.zip")) == []


def test_native_ad_is_ambiguous():
    f = rules.check_disguised_ad(el(kind="link", text="Doctors hate this one simple trick for back pain",
                                    near_text="Sponsored stories"))
    assert f and f[0].confidence < 0.8


# ---------------------------------------------------------------- runner

def test_run_rules_dedupes_per_element_and_type():
    page = [el(text="Hurry, sale ends in 5:00! Last chance!", selector="#a")]
    f = rules.run_rules(page)
    assert len([x for x in f if x.pattern_type == PT.FAKE_URGENCY]) == 1


def test_clean_page_has_no_findings():
    page = [el(text="Welcome to our store"), el(kind="button", text="Add to cart"),
            el(kind="price", text="$24.00"), el(kind="checkbox", checked=False, label="Gift message")]
    assert rules.run_rules(page) == []
