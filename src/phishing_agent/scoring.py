"""Configurable rule-based scoring with explicit, explainable contributions."""

from dataclasses import dataclass

from .schemas import FeatureSet, RiskLabel


@dataclass(frozen=True)
class ScoreThresholds:
    medium: int = 30
    high: int = 60

    def __post_init__(self):
        if not 0 <= self.medium < self.high <= 100:
            raise ValueError("thresholds must satisfy 0 <= medium < high <= 100")


def risk_label(score: int, thresholds: ScoreThresholds = ScoreThresholds()) -> RiskLabel:
    if score >= thresholds.high:
        return RiskLabel.HIGH
    if score >= thresholds.medium:
        return RiskLabel.MEDIUM
    return RiskLabel.LOW


def score_features(features: FeatureSet) -> tuple[int, list[str]]:
    """Return a 0-100 heuristic score and evidence; it is not a probability."""
    score = 0
    evidence: list[str] = []

    def add(points: int, reason: str) -> None:
        nonlocal score
        score += points
        evidence.append(reason)

    if features.urgency_terms:
        add(min(18, 6 + 3 * len(features.urgency_terms)),
            "Urgency or pressure language: " + ", ".join(features.urgency_terms[:5]) + ".")
    if features.credential_terms:
        add(min(18, 6 + 3 * len(features.credential_terms)),
            "Credential/account language: " + ", ".join(features.credential_terms[:5]) + ".")
    if features.payment_terms:
        add(min(24, 8 + 4 * len(features.payment_terms)),
            "Payment or financial-change language: " + ", ".join(features.payment_terms[:5]) + ".")
    if features.url_count:
        add(min(12, 3 + 3 * features.url_count),
            f"Contains {features.url_count} URL(s): " + ", ".join(features.urls_defanged[:4]) + ".")
    if features.suspicious_url_patterns:
        add(min(16, 8 * len(features.suspicious_url_patterns)),
            "URL structure indicator(s): " + "; ".join(features.suspicious_url_patterns[:3]) + ".")
    if features.domain_mismatch:
        add(16, f"Reply-To domain differs from sender domain ({features.sender_domain} vs. {features.reply_to_domain}).")
    if features.authentication_failures:
        add(min(24, 8 * len(features.authentication_failures)),
            "User-supplied authentication results report: " + ", ".join(features.authentication_failures) + ".")
    if features.risky_extensions:
        add(16, "Attachment metadata lists potentially risky extension(s): " + ", ".join(features.risky_extensions) + ".")
    return min(100, score), evidence
