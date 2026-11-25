"""Request/response models shared by the API, classifier and tests."""
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


class PatternType(str, Enum):
    FAKE_URGENCY = "fake_urgency"
    FAKE_SCARCITY = "fake_scarcity"
    PRESELECTED_OPTION = "preselected_option"
    HIDDEN_FEES = "hidden_fees"
    CONFIRMSHAMING = "confirmshaming"
    FORCED_CONSENT = "forced_consent"
    DISGUISED_AD = "disguised_ad"


ElementKind = Literal["text", "button", "link", "checkbox", "radio", "timer", "price", "banner"]


class PageElement(BaseModel):
    """One element extracted from the page by the content script."""
    selector: str = Field(max_length=1000)
    kind: ElementKind
    text: str = Field(default="", max_length=1000)
    checked: Optional[bool] = None       # checkboxes / radios
    label: str = Field(default="", max_length=500)       # label of a checkbox / radio
    near_text: str = Field(default="", max_length=1000)  # text of the surrounding container
    href: str = Field(default="", max_length=2000)
    ad_hint: bool = False                # element or ancestor looks like an ad slot
    changing: bool = False               # timer text changed between two samples


class Finding(BaseModel):
    pattern_type: PatternType
    confidence: float = Field(ge=0, le=1)
    element_selector: str
    explanation: str
    source: Literal["rule", "llm", "rule+llm"] = "rule"


Mode = Literal["rules", "llm", "hybrid"]


class AnalyzeRequest(BaseModel):
    url: str = Field(max_length=2000)
    elements: list[PageElement] = Field(default_factory=list, max_length=500)
    mode: Mode = "hybrid"
    include_threat: bool = True


class ThreatRequest(BaseModel):
    url: str = Field(max_length=2000)


class ThreatSignal(BaseModel):
    name: str                   # safe_browsing | domain_age | ssl | redirects
    status: Literal["ok", "warn", "bad", "unknown"]
    detail: str
    data: dict = Field(default_factory=dict)


class ThreatReport(BaseModel):
    url: str
    signals: list[ThreatSignal]


class AnalyzeResponse(BaseModel):
    url: str
    risk_score: int = Field(ge=0, le=100)
    findings: list[Finding]
    threat: Optional[ThreatReport] = None
    llm_used: bool = False
    llm_error: Optional[str] = None
