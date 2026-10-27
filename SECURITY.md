# Security and safe-use notes

## Scope

This repository is an educational triage example, not a production mail-security control. It has no production hardening, authenticated access, durable audit trail, guarantee of confidentiality, or operational response process. Do not rely on its labels to accept, reject, quarantine, or report real mail automatically.

## Processing boundaries

- Input is parsed locally and validated for field lengths, message content, row count, and upload size. CSV rows fail independently where possible.
- URLs are regex-extracted and parsed locally. The program does not perform DNS resolution, HTTP requests, reputation queries, redirects, link opening, or domain verification. URLs are defanged in application displays and dataset downloads.
- Attachment metadata is text only. The application accepts no attachment upload and never opens or executes a file.
- Pasted headers are parsed with Python's email parser without fetching messages.
- Authentication results are observations supplied by the user. A pass/fail string is not cryptographically checked or independently verified.
- Email text is untrusted data and cannot change analysis rules. The deterministic explanation does not execute or follow embedded instructions. No LLM, external API, shell, or arbitrary tool integration is configured.
- No complete message bodies are logged by the application. Users should still avoid pasting confidential messages into a demo.
- Result CSV output prefixes formula-like cells to reduce spreadsheet formula injection.
- Streamlit usage telemetry is disabled and the server binds to loopback by default; the app is not exposed to the local network unless the operator explicitly changes its configuration.

## Model and decision limits

Rules are transparent heuristics, not probabilities. Optional ML is an educational local text classifier and can be biased by its synthetic training examples. Scores are triage cues only. False positives and false negatives are expected; review evidence in context and verify consequential requests through a separate trusted channel.

Model artifacts are loaded only from the local ignored `models/phishing_model.joblib` path. Do not load artifacts from untrusted sources. Dependencies should be installed and updated using a trusted package index.

## Reporting

Do not submit real credentials, live malicious samples, or personal email data as bug reports. Report a reproducible software issue without sensitive message content.
