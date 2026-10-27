"""Feature extraction regressions."""

from src.phishing_agent.features import extract_features
from src.phishing_agent.schemas import EmailRecord


def test_features_cover_risky_url_metadata_and_language():
    record = EmailRecord.model_validate({
        "sender": "notice@sender.example",
        "reply_to": "reply@other.example",
        "subject": "Urgent, act now",
        "body": "Sign in with your password at hxxp://192.168.1.2/login",
        "auth_results": "SPF fail; DKIM pass",
        "attachment_metadata": "report.xlsm",
    })
    features = extract_features(record)
    assert features.domain_mismatch
    assert features.url_count == 1
    assert features.urls_defanged == ["hxxp://192[.]168[.]1[.]2/login"]
    assert features.urgency_terms
    assert features.credential_terms
    assert features.authentication_failures == ["SPF FAIL"]
    assert features.risky_extensions == [".xlsm"]
    assert features.suspicious_url_patterns


def test_reserved_example_domain_is_not_an_intrinsic_suspicious_pattern():
    record = EmailRecord.model_validate({"body": "See https://portal.university.example/agenda"})
    features = extract_features(record)
    assert features.url_count == 1
    assert features.suspicious_url_patterns == []
