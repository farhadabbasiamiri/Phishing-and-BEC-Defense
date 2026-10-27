# Architecture

`app.py` is the Streamlit presentation layer. It validates single-email form input with `EmailRecord` or delegates bounded batch parsing to `csv_io.validate_csv_bytes`. Both paths call the deterministic `agent.analyze_email` orchestrator.

The core sequence is:

1. `parser.py` extracts URL-shaped text and parses pasted RFC-style headers locally.
2. `features.py` extracts domains, defanged URLs, language indicators, user-supplied authentication failures, risky attachment extensions, and prompt-injection indicators.
3. `scoring.py` calculates a transparent 0–100 rule score with fixed feature contributions and configurable risk thresholds.
4. `classifier.py` optionally loads a local scikit-learn text pipeline. It never downloads a model.
5. `agent.py` combines evidence, decision mode, uncertainty, summary, and recommended actions into validated Pydantic output.

Modes are rules (default), ML, and a 70% heuristic / 30% ML probability combination. When the model is absent the agent explicitly falls back to rules. No code path visits URLs, inspects attachment bytes, invokes an LLM, or sends message content to an external service. Streamlit usage telemetry is disabled and local execution binds to loopback.