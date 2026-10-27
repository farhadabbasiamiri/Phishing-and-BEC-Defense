"""Optional local scikit-learn text classifier; no network or automatic downloads."""

from pathlib import Path
from typing import Any

ARTIFACT = Path(__file__).resolve().parents[2] / "models" / "phishing_model.joblib"


def _sklearn_components():
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import FeatureUnion, Pipeline
        return TfidfVectorizer, LogisticRegression, FeatureUnion, Pipeline
    except ImportError:
        return None


def make_model():
    components = _sklearn_components()
    if components is None:
        raise RuntimeError("scikit-learn is not installed; install requirements.txt to train/use the optional model")
    TfidfVectorizer, LogisticRegression, FeatureUnion, Pipeline = components
    text = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=8_000, sublinear_tf=True)),
        ("char", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2, max_features=8_000, sublinear_tf=True)),
    ])
    return Pipeline([
        ("text", text),
        ("classifier", LogisticRegression(C=2.0, class_weight="balanced", max_iter=1_000, random_state=42)),
    ])


def email_text(record: dict[str, Any]) -> str:
    return "\n".join(str(record.get(key, "") or "") for key in (
        "sender", "reply_to", "subject", "body", "auth_results", "attachment_metadata"
    ))


def load_model(path: str | Path = ARTIFACT):
    artifact = Path(path)
    if not artifact.is_file():
        return None, f"Optional ML model is not trained ({artifact.name} is missing); deterministic rules are used."
    try:
        import joblib
        return joblib.load(artifact), None
    except (ImportError, OSError, ValueError, EOFError) as exc:
        return None, f"Optional ML model could not be loaded ({type(exc).__name__}); deterministic rules are used."


def predict_probability(model, record: dict[str, Any]) -> float | None:
    if model is None:
        return None
    probabilities = model.predict_proba([email_text(record)])[0]
    classes = list(model.classes_)
    positive = next((i for i, label in enumerate(classes) if str(label).lower() in {"phishing", "suspicious"}), None)
    if positive is None:
        return None
    return float(probabilities[positive])
