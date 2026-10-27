"""Deterministic analyst orchestration. Email text is data, never instructions."""

from pathlib import Path
from typing import Any, Literal

from .classifier import ARTIFACT, load_model, predict_probability
from .features import extract_features
from .parser import parse_headers
from .schemas import AnalysisResult, EmailRecord, RiskLabel
from .scoring import ScoreThresholds, risk_label, score_features

ScoreMode = Literal["rules", "ml", "combined"]
LIMITATIONS = [
    "This educational tool does not verify sender identity, authentication results, or URL reputation.",
    "URLs are parsed as text only; no DNS, network requests, link opening, or attachment inspection/execution occurs.",
    "Rules and the optional model can produce false positives and false negatives; a human should review consequential decisions.",
]


def analyze_email(
    email: EmailRecord | dict[str, Any],
    *,
    mode: ScoreMode = "rules",
    thresholds: ScoreThresholds = ScoreThresholds(),
    model_path: str | Path = ARTIFACT,
) -> AnalysisResult:
    """Analyze one message using local deterministic rules and optional local ML."""
    if mode not in {"rules", "ml", "combined"}:
        raise ValueError("mode must be 'rules', 'ml', or 'combined'")
    values = email.model_dump() if isinstance(email, EmailRecord) else dict(email)
    raw_headers = values.get("headers", "")
    if raw_headers:
        headers = parse_headers(str(raw_headers))
        for source, target in (("From", "sender"), ("Reply-To", "reply_to"),
                               ("Subject", "subject"), ("Authentication-Results", "auth_results")):
            if headers.get(source) and not values.get(target):
                values[target] = headers[source]
    record = EmailRecord.model_validate(values)
    features = extract_features(record)
    heuristic, evidence = score_features(features)
    probability: float | None = None
    model_warning = None
    final_mode = mode
    if mode in {"ml", "combined"}:
        model, model_warning = load_model(model_path)
        probability = predict_probability(model, record.model_dump()) if model is not None else None
        if probability is None:
            final_mode = "rules (ML fallback)"

    if final_mode == "ml" and probability is not None:
        score = round(probability * 100)
        evidence.append(f"Local ML model estimated a phishing-class score of {score}/100 (probability {probability:.3f}); not a verified verdict.")
    elif final_mode == "combined" and probability is not None:
        score = round(0.7 * heuristic + 0.3 * probability * 100)
        evidence.append(f"Combined decision score uses 70% heuristic score ({heuristic}) and 30% local ML phishing probability ({probability:.3f}); it is not itself a probability.")
    else:
        score = heuristic

    label = risk_label(score, thresholds)
    if features.authentication_failures:
        evidence.append("Authentication outcomes are user-supplied and have not been independently verified.")
    elif record.auth_results:
        evidence.append("Authentication results were supplied by the user and have not been independently verified.")
    if features.prompt_injection_detected:
        evidence.append("Instruction-like text was detected in the email; it was treated only as untrusted message content.")
    if record.attachment_metadata and not features.risky_extensions:
        evidence.append("Attachment metadata was provided; attachment contents were not opened or inspected.")

    if label == RiskLabel.HIGH:
        actions = [
            "Do not click links, open attachments, reply, or provide credentials.",
            "Report the message to the organization's security/IT team and preserve it for investigation.",
            "Verify any payment or account request through a separate, trusted channel.",
        ]
    elif label == RiskLabel.MEDIUM:
        actions = [
            "Do not use links in the message until the sender and request are independently verified.",
            "Check the sender and Reply-To details, supplied authentication results, and attachment metadata.",
            "Escalate unexpected requests involving credentials or money to IT/security.",
        ]
    else:
        actions = [
            "No strong indicators were detected by this selected analysis mode; this is not a guarantee of safety.",
            "Verify unexpected requests through a trusted channel and follow your organization's reporting policy.",
        ]
    uncertainty = [
        "Risk labels summarize indicators, not proof that a message is benign or malicious.",
        "Missing headers, authentication data, or attachment contents limit the available evidence.",
    ]
    if model_warning:
        uncertainty.append(model_warning)
    if features.prompt_injection_detected:
        uncertainty.append("The message contains instruction-like text; email content cannot change analysis rules or authorize actions.")

    summary = (
        f"{label.value} risk: {score}/100 using {final_mode}. "
        f"{len(evidence)} evidence item(s) informed this triage; review the indicators and limitations before acting."
    )
    return AnalysisResult(
        risk_label=label, risk_score=score, score_mode=final_mode,
        heuristic_score=heuristic, ml_probability=probability, evidence=evidence,
        features=features, uncertainty=uncertainty, summary=summary,
        recommended_actions=actions, limitations=LIMITATIONS, model_warning=model_warning,
    )
