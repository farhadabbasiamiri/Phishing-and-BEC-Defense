"""Allow ``python -m phishing_agent`` as an import smoke test."""

from .agent import analyze_email

if __name__ == "__main__":
    result = analyze_email({"subject": "Routine meeting", "body": "See you at the meeting tomorrow."})
    print(result.model_dump_json(indent=2))
