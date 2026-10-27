"""Backward-compatible imports for the original coursework demo."""

from src.phishing_agent.agent import analyze_email as _analyze_email
from src.phishing_agent.parser import defang_url, extract_urls


def normalize_email_row(row):
    aliases = {
        "sender": ("sender", "from", "from_address"),
        "reply_to": ("reply_to", "reply-to"),
        "subject": ("subject",),
        "body": ("body", "text", "email_body"),
        "auth_results": ("auth_results", "authentication", "authentication_results"),
        "attachment_metadata": ("attachment_metadata", "attachments", "attachment"),
    }
    normalized = {str(key).strip().lower(): value for key, value in row.items()}
    return {
        target: next((str(normalized[key]) for key in names if key in normalized and normalized[key] is not None), "")
        for target, names in aliases.items()
    }


def analyze_email(email):
    return _analyze_email(normalize_email_row(email)).to_dict()
