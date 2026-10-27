# Group 2A: Phishing Email Investigation Agent

An offline-first, explainable educational email-triage application. Paste one email or upload a CSV to get a Low/Medium/High risk label, a transparent decision score, evidence, uncertainty, and suggested next steps.

> **Educational tool only — not a production security control.** A low score does not prove a message is safe, and a high score does not prove it is malicious. Have a human investigate consequential messages.

## Safety and privacy

- No email content is sent to an external API. No LLM is required or configured.
- The deterministic analyst treats email content as untrusted data, never as instructions.
- URLs are extracted as strings only: no DNS lookups, network requests, reputation queries, redirects, or link opening. They are defanged for display.
- Attachment metadata (names/extensions) may be analyzed; attachment bytes are never accepted, opened, downloaded, or executed.
- SPF/DKIM/DMARC observations are user-supplied and are **not independently verified**.
- Avoid pasting real confidential email. The app does not persist submissions intentionally, but local Streamlit/session and browser behavior is outside this project's guarantees.

See [SECURITY.md](SECURITY.md) and [DATA_CARD.md](DATA_CARD.md).

## Requirements

Python 3.11 or newer, pip, and a normal desktop browser. The included commands are tested with the Python version installed on your system. The core rules-only application works without a trained model; dependencies are installed from `requirements.txt`. Internet access is needed only to install Python packages, not to analyze mail. scikit-learn and joblib are optional at runtime for rules-only use but are included so the optional classifier can be trained.

## Windows PowerShell quick start

From the project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python scripts/generate_data.py
python scripts/train_model.py
python scripts/evaluate_model.py
pytest -q
streamlit run app.py
```

If PowerShell prevents environment activation, use `.\.venv\Scripts\python.exe -m pip install -r requirements.txt` and prefix the Python commands below with `.\.venv\Scripts\python.exe`; run Streamlit with `.\.venv\Scripts\streamlit.exe run app.py`.

## macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python scripts/generate_data.py
python scripts/train_model.py
python scripts/evaluate_model.py
pytest -q
streamlit run app.py
```

Open the local URL printed by Streamlit. To run rules-only, skip model training and select **rules** in the sidebar. Model/LLM absence is handled gracefully.

## Docker (optional)

```bash
docker build -t spam-project .
docker run --rm -p 8501:8501 spam-project
```

Open `http://localhost:8501`. The image starts in rules-fallback mode; train a local model outside the container if desired. Streamlit binds to the container interface for port forwarding; local non-container runs bind to `127.0.0.1`.

## Using the dashboard

1. **Single email:** paste sender, Reply-To, subject, body, user-supplied authentication results, and optional attachment *metadata*. Pasted RFC-style headers can fill otherwise-empty sender, Reply-To, subject, and authentication fields. Load either built-in fictional sample with the example buttons.
2. **CSV batch:** select a UTF-8 CSV up to 5 MB and 5,000 rows. At least one of `subject` or `body` must be a column; each row must contain at least one non-empty message field. Other columns are optional. Invalid rows are reported independently and do not discard valid rows.
3. **Dataset exploration:** inspect and download the balanced, synthetic sample dataset. Displayed URLs are defanged.
4. **Model & evaluation:** inspect decision-mode formulas, model availability, and reproducible evaluation instructions.

CSV accepts these column aliases (case-insensitive): `sender` (`from`, `from_address`), `reply_to` (`reply-to`), `subject`, `body` (`text`, `email_body`), `auth_results` (`authentication`, `authentication_results`), `attachment_metadata` (`attachments`, `attachment`), and `headers` (`raw_headers`, `email_headers`). Optional `id` and `label` columns are ignored by inference; **labels are never model inputs**. Output CSV sanitizes spreadsheet formula prefixes.

## Decision and scoring

Default mode is deterministic **rules**. The rule score is a heuristic from 0 to 100, not a probability. Default label thresholds are Low `<30`, Medium `30–59`, High `≥60`. The rule evidence and baseline contributions are implemented in `src/phishing_agent/scoring.py` and signal extraction in `src/phishing_agent/features.py`. A URL's presence alone is a weak indicator, not a finding of maliciousness; reserved `.example` domains are inert examples.

The optional scikit-learn text pipeline combines word and character TF-IDF with logistic regression. Its probability is shown separately as `ml_probability`:

- **rules:** final decision score = heuristic score.
- **ml:** final decision score = rounded `100 × ML phishing-class probability`.
- **combined:** final decision score = rounded `0.70 × heuristic + 0.30 × 100 × ML phishing-class probability`.

The selected risk thresholds apply to each final decision score. If the model is missing or unavailable, ML and combined modes explicitly fall back to rules and expose a warning. No probability is inferred from the heuristic score.

## Dataset and evaluation

Regenerate 300 balanced synthetic records with:

```bash
python scripts/generate_data.py
```

Train the optional model with `python scripts/train_model.py`. This trains the deployment artifact at `models/phishing_model.joblib` on all rows; it is git-ignored. Evaluate separately with `python scripts/evaluate_model.py`: this command uses a seeded, stratified 75/25 split and fits its own word/character vectorizers only on the training partition. It prints macro precision, recall, F1, a confusion matrix, and per-class metrics from the actual run. Results on this small, repetitive synthetic dataset are illustrative and are not estimates of production detection rates. Read [DATA_CARD.md](DATA_CARD.md) for dataset limitations and [SECURITY.md](SECURITY.md) for threat boundaries.

## Project structure

```text
app.py                         Streamlit dashboard
phishing_agent.py              Compatibility API for earlier coursework imports
src/phishing_agent/             Validation, parser, features, scoring, ML, safety, orchestration
data/dummy_emails.csv          Generated fictional 300-row dataset
scripts/generate_data.py       Reproducible dataset generator
scripts/train_model.py         Optional local-model training
scripts/evaluate_model.py      Stratified held-out evaluation
tests/                         pytest unit and safety regression tests
requirements.txt               Bounded maintained dependencies
DATA_CARD.md                   Dataset documentation
SECURITY.md                    Security model and safe-use guidance
docs/                          Architecture, field reference, evaluation, limitations
```

## Run checks

```bash
pytest -q
python -m src.phishing_agent
```

The second command is a lightweight import and analysis smoke test. `python -m compileall -q app.py src scripts tests` can additionally check Python syntax. Avoid putting real email exports or credentials in the repository. Real mail formats, diverse language, benign-but-urgent requests, and attacker adaptation are not represented by the examples; false positives and false negatives are expected.
