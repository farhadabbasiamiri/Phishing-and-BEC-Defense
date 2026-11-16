# PhishScope: explainable phishing triage agent
Defensive use only. Graduate capstone, Group 2A (Laurentian University, Fall 2026).

Paste an email or upload a CSV and get a risk label, evidence, defanged URL findings, safe guidance for the
recipient, and proposed analyst actions. Sensitive actions need human approval and are written to an audit log.

## Run it in VS Code
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate      macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python make_data.py        # 500 synthetic emails -> data/emails.csv
python evaluate.py         # trains the ML model, writes results/eval_report.md
streamlit run app.py       # dashboard at http://localhost:8501
```
Run `evaluate.py` once before the app so the ML component is active (without it the app uses rules only).
Tests: `pytest -q tests`. VS Code: Run and Debug panel has launch configs for each script.

## Optional local LLM (Ollama)
Install Ollama, make sure the model appears in `ollama list` (for example, run `ollama pull qwen2.5:3b`), then
tick "Use local LLM" in the sidebar. The app lists models reported by the running Ollama service and selects an
installed model by default; if it cannot list models, enter a model name manually. The LLM only writes the
explanation; it never decides the verdict, sees defanged text inside delimiters, and its output is stripped of
live URLs. If Ollama is not running the app falls back to a template explanation.

## Architecture
`parse_raw/normalize` -> `check_url` (offline lookalike, mismatch, IP, shortener, TLD) -> `extract_features`
-> `rule_score` (transparent weights) + `ML` (logistic regression) -> hybrid score -> explanation
(LLM or template) -> `propose_actions` -> human approval -> audit log.

| File | Owner suggestion |
|---|---|
| `phishscope/generator.py`, `make_data.py`, `data/` | Data Lead |
| `phishscope/scorer.py` (rules + ML), `evaluate.py` | AI Lead |
| `phishscope/analysis.py`, `phishscope/agent.py` | Agent Lead |
| `app.py` | App Lead |
| `tests/`, `results/`, `samples/` | Evaluation Lead |

## CSV format
`id, subject, from, reply_to, return_path, spf, dkim, dmarc, attachments, body` (`label` optional;
attachments separated by `;`). Defang URLs as `hxxps://example[.]com`.

## Safety design
No URL is ever fetched, opened or rendered. All URLs are shown defanged. Prompt-injection text inside an email is
treated as data and flagged as an indicator. Block/quarantine/notify actions are simulated and gated by approval.

## Known limitations (state these in your report)
- The dataset is synthetic and template-based, so the ML model scores near 100% on it. That does NOT predict
  real-world accuracy. The rule score's false positives on the hard negatives (urgent IT notices, marketing with
  shorteners) are the more honest signal. Next steps: add real samples (CIC datasets), leave-one-category-out
  evaluation, and a larger hard-negative set.
- The lookalike brand list is small; no live reputation feeds (PhishTank/URLhaus snapshot lookups are future work).
- No attachment sandboxing; only names and extensions are checked.
- Small local LLMs can be inconsistent, which is why they only explain.
