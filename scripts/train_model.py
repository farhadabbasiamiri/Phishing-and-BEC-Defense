"""Train the optional local text model and save it under models/."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import joblib
import pandas as pd

from src.phishing_agent.classifier import ARTIFACT, make_model, email_text


def main() -> None:
    dataset = ROOT / "data" / "dummy_emails.csv"
    frame = pd.read_csv(dataset, dtype=str, keep_default_na=False)
    if not {"body", "subject", "label"}.issubset(frame.columns):
        raise SystemExit("Dataset must include subject, body, and label columns.")
    model = make_model()
    model.fit([email_text(row) for row in frame.to_dict(orient="records")], frame["label"])
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, ARTIFACT)
    print(f"Trained on {len(frame)} synthetic rows; saved optional model to {ARTIFACT}")
    print("The label column was used only as the target, never as an input feature.")


if __name__ == "__main__":
    main()
