"""Core end-to-end analyst behavior."""

from pydantic import ValidationError
import pytest

from src.phishing_agent.agent import analyze_email
from src.phishing_agent.schemas import EmailRecord, RiskLabel


def test_benign_email_is_low_with_caveat():
    result = analyze_email({
        "sender": "alex@university.example",
        "subject": "Meeting notes",
        "body": "Here are the project notes. Review them when convenient.",
    })
    assert result.risk_label is RiskLabel.LOW
    assert result.risk_score == 0
    assert "not a guarantee" in result.recommended_actions[0]


def test_high_risk_email_lists_explainable_indicators():
    result = analyze_email({
        "sender": "security@sender.example",
        "reply_to": "reply@other.example",
        "subject": "Urgent verify your account",
        "body": "Your password will expire today. Sign in immediately at http://login.example/verify",
        "auth_results": "SPF fail; DKIM fail; DMARC fail",
        "attachment_metadata": "account.html",
    })
    assert result.risk_label is RiskLabel.HIGH
    assert result.risk_score >= 60
    assert result.heuristic_score == result.risk_score
    assert result.ml_probability is None
    assert any("Reply-To domain" in item for item in result.evidence)
    assert any("SPF FAIL" in item for item in result.evidence)
    assert all("[.]" in item for item in result.features.urls_defanged)


def test_sender_reply_to_mismatch_is_exposed():
    result = analyze_email({
        "sender": "sender@university.example",
        "reply_to": "answer@different.example",
        "subject": "Hello",
        "body": "A short message.",
    })
    assert result.features.domain_mismatch
    assert result.features.sender_domain == "university.example"
    assert result.features.reply_to_domain == "different.example"


def test_authentication_results_are_explicitly_unverified():
    result = analyze_email({
        "subject": "Routine note",
        "body": "Please see the meeting time.",
        "auth_results": "SPF pass; DKIM pass; DMARC pass",
    })
    assert any("not been independently verified" in item for item in result.evidence)


def test_header_only_message_uses_parsed_headers():
    result = analyze_email({
        "headers": "From: Alex <alex@university.example>\nSubject: A note\n\n",
        "body": "We will meet next week.",
    })
    assert result.features.sender_domain == "university.example"
    assert result.risk_label is RiskLabel.LOW


@pytest.mark.parametrize("values", [
    {"subject": "", "body": ""},
    {"subject": "x" * 2_001, "body": "text"},
    {"sender": "not-an-address", "subject": "x", "body": "text"},
])
def test_invalid_or_empty_email_rejected(values):
    with pytest.raises(ValidationError):
        EmailRecord.model_validate(values)


def test_missing_optional_fields_are_accepted():
    record = EmailRecord.model_validate({"body": "Message content"})
    assert record.sender == ""
    assert record.auth_results == ""


def test_thresholds_and_score_modes_validate():
    result = analyze_email({"body": "Short note"}, mode="combined", model_path="missing.joblib")
    assert result.score_mode == "rules (ML fallback)"
    assert result.model_warning
    with pytest.raises(ValueError):
        analyze_email({"body": "Short note"}, mode="other")
