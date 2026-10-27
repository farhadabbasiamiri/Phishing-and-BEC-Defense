"""Validated input and output models for the analyst pipeline."""

from enum import Enum
from email.utils import parseaddr
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class RiskLabel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class EmailRecord(BaseModel):
    """An email and user-supplied metadata; no content is fetched or executed."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")

    sender: str = Field(default="", max_length=500)
    reply_to: str = Field(default="", max_length=500)
    subject: str = Field(default="", max_length=2_000)
    body: str = Field(default="", max_length=100_000)
    auth_results: str = Field(default="", max_length=2_000)
    attachment_metadata: str = Field(default="", max_length=4_000)
    headers: str = Field(default="", max_length=30_000)

    @field_validator("sender", "reply_to")
    @classmethod
    def validate_address(cls, value: str) -> str:
        if value:
            _, address = parseaddr(value)
            domain = address.rsplit("@", 1)[-1].rstrip(".").lower()
            labels = domain.split(".")
            if (
                not address or address.count("@") != 1
                or any(character.isspace() for character in address)
                or len(labels) < 2
                or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
            ):
                raise ValueError("must contain a plausible email address")
        return value

    @model_validator(mode="after")
    def require_message_content(self) -> "EmailRecord":
        if not self.subject and not self.body:
            raise ValueError("email must include a subject or body")
        return self


class FeatureSet(BaseModel):
    url_count: int = 0
    urls_defanged: list[str] = Field(default_factory=list)
    sender_domain: str = ""
    reply_to_domain: str = ""
    domain_mismatch: bool = False
    urgency_terms: list[str] = Field(default_factory=list)
    credential_terms: list[str] = Field(default_factory=list)
    payment_terms: list[str] = Field(default_factory=list)
    risky_extensions: list[str] = Field(default_factory=list)
    authentication_failures: list[str] = Field(default_factory=list)
    suspicious_url_patterns: list[str] = Field(default_factory=list)
    prompt_injection_detected: bool = False


class AnalysisResult(BaseModel):
    """Decision, evidence, and advice. Heuristic and ML scores stay distinct."""

    risk_label: RiskLabel
    risk_score: int = Field(ge=0, le=100, description="Decision score, not a probability")
    score_mode: str
    heuristic_score: int = Field(ge=0, le=100)
    ml_probability: float | None = Field(default=None, ge=0, le=1)
    evidence: list[str] = Field(default_factory=list)
    features: FeatureSet
    uncertainty: list[str] = Field(default_factory=list)
    summary: str
    recommended_actions: list[str]
    limitations: list[str]
    model_warning: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
