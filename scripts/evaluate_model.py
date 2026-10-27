"""Evaluate an untouched stratified test split using a train-only text pipeline."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from src.phishing_agent.classifier import email_text, make_model


def main() -> None:
    frame = pd.read_csv(ROOT / "data" / "dummy_emails.csv", dtype=str, keep_default_na=False)
    records = frame.to_dict(orient="records")
    texts = [email_text(record) for record in records]
    labels = frame["label"].to_numpy()
    train_indices, test_indices = train_test_split(
        range(len(labels)), test_size=0.25, random_state=42, stratify=labels
    )
    model = make_model()
    model.fit([texts[i] for i in train_indices], labels[train_indices])
    predictions = model.predict([texts[i] for i in test_indices])
    expected = labels[test_indices]
    print(f"Illustrative synthetic-data holdout: {len(train_indices)} train / {len(test_indices)} test; seed=42")
    print(f"Precision (macro): {precision_score(expected, predictions, average='macro', zero_division=0):.3f}")
    print(f"Recall (macro):    {recall_score(expected, predictions, average='macro', zero_division=0):.3f}")
    print(f"F1 (macro):        {f1_score(expected, predictions, average='macro', zero_division=0):.3f}")
    print("Confusion matrix (rows=true, columns=predicted; benign, suspicious):")
    print(confusion_matrix(expected, predictions, labels=["benign", "suspicious"]))
    print("Per-class metrics:")
    print(classification_report(expected, predictions, labels=["benign", "suspicious"], zero_division=0))
    print("Synthetic examples are repetitive and do not estimate performance on real mail.")


if __name__ == "__main__":
    main()
