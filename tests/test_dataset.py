"""Dataset contract and synthetic-content checks."""

import pandas as pd

from scripts.generate_data import build_records
from src.phishing_agent.classifier import email_text


def test_generator_is_reproducible_balanced_and_uses_synthetic_domains():
    first, second = build_records(), build_records()
    assert first == second
    frame = pd.DataFrame(first)
    assert len(frame) >= 240
    assert frame["id"].is_unique
    assert frame["label"].value_counts().to_dict() == {"benign": 150, "suspicious": 150}
    joined = " ".join(frame.astype(str).to_numpy().ravel())
    assert ".example" in joined
    assert "http://" not in joined and "https://" not in joined


def test_model_input_does_not_include_label():
    record = {"subject": "A message", "body": "Hello", "label": "suspicious"}
    text = email_text(record)
    assert "suspicious" not in text
    assert "A message" in text
