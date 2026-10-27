"""End-to-end pipeline mode behavior without a filesystem model artifact."""

import numpy as np

from src.phishing_agent.agent import analyze_email


class FixedModel:
    classes_ = np.array(["benign", "suspicious"])

    def predict_proba(self, texts):
        assert len(texts) == 1
        return np.array([[0.2, 0.8]])


def test_ml_and_combined_decisions_keep_probability_separate(monkeypatch):
    monkeypatch.setattr("src.phishing_agent.agent.load_model", lambda path: (FixedModel(), None))
    email = {
        "subject": "Urgent payment request",
        "body": "Please make a payment today.",
    }
    ml = analyze_email(email, mode="ml")
    combined = analyze_email(email, mode="combined")
    assert ml.ml_probability == 0.8
    assert ml.risk_score == 80
    assert ml.heuristic_score != ml.risk_score
    assert combined.ml_probability == 0.8
    assert combined.risk_score == round(0.7 * combined.heuristic_score + 0.3 * 80)
    assert combined.score_mode == "combined"
