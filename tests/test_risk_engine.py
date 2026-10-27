"""Rule score thresholds and score boundaries."""

import pytest

from src.phishing_agent.schemas import FeatureSet, RiskLabel
from src.phishing_agent.scoring import ScoreThresholds, risk_label, score_features


def test_default_risk_threshold_boundaries():
    assert risk_label(0) is RiskLabel.LOW
    assert risk_label(29) is RiskLabel.LOW
    assert risk_label(30) is RiskLabel.MEDIUM
    assert risk_label(59) is RiskLabel.MEDIUM
    assert risk_label(60) is RiskLabel.HIGH
    assert risk_label(100) is RiskLabel.HIGH


def test_thresholds_are_configurable_and_validated():
    thresholds = ScoreThresholds(medium=20, high=80)
    assert risk_label(20, thresholds) is RiskLabel.MEDIUM
    assert risk_label(80, thresholds) is RiskLabel.HIGH
    with pytest.raises(ValueError):
        ScoreThresholds(medium=60, high=30)


def test_rule_score_is_bounded_and_evidence_is_explainable():
    features = FeatureSet(
        urgency_terms=["urgent", "today", "act now"],
        credential_terms=["password", "sign in"],
        payment_terms=["payment", "gift card"],
        url_count=12,
        urls_defanged=["hxxp://example[.]example"],
        suspicious_url_patterns=["numeric host"] * 5,
        domain_mismatch=True,
        authentication_failures=["SPF FAIL", "DKIM FAIL", "DMARC FAIL"],
        risky_extensions=[".exe"],
    )
    score, reasons = score_features(features)
    assert score == 100
    assert reasons
    assert all(isinstance(reason, str) for reason in reasons)
