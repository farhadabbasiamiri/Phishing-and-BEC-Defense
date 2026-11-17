# Project Status and Team Work Plan

## Purpose and current status

This document maps the current repository to the proposed seven-slide project presentation, records what is already implemented, and identifies the work still needed. It is based on the code and documentation in this repository; it does not claim who completed earlier work. The five-person role split below is a proposed allocation, since no team-member names or contribution history were provided.

**Current project:** an offline-first educational email triage application for suspicious email and business email compromise (BEC) indicators. A user can analyze one email or a CSV batch and review a Low/Medium/High risk label, score, evidence, uncertainty, and recommended next steps.

**Important scope distinction:** the repository has a deterministic rule-based analyst and an optional local scikit-learn text classifier. It does **not** currently implement retrieval-augmented generation (RAG), a generative LLM, autonomous tool use, or a production email-security integration. Do not present any of those as completed features. Decide as a team whether RAG is a future extension or outside the project requirements.

## What has been done

### Application and analysis pipeline

- Built a Streamlit dashboard with single-email analysis, CSV batch analysis, dataset exploration, and model/evaluation information.
- Added local parsing and input validation, including optional RFC-style headers, common CSV column aliases, per-row validation, and upload limits.
- Implemented feature extraction for urgency, credential and payment language, sender/Reply-To domain mismatch, URL patterns, user-supplied SPF/DKIM/DMARC failures, attachment filename extensions, and instruction-like text.
- Implemented a transparent heuristic risk score from 0 to 100 and configurable Low/Medium/High thresholds.
- Added an optional word/character TF-IDF plus logistic-regression classifier, with rules-only fallback if the model is unavailable.
- Supports rules, ML, and combined scoring modes. The combined score uses 70% heuristic and 30% model probability; heuristic score and ML probability are presented as different quantities.
- Added analyst evidence, uncertainty, limitations, and recommended actions to the structured analysis result.

### Dataset, training, and evaluation

- Added a reproducible generator for 300 balanced, fictional records (150 benign and 150 suspicious), with a fixed seed and reserved `.example` domains.
- Documented dataset columns, intended use, generation assumptions, limitations, and safe-use expectations.
- Added a training script for the optional local model and a separate stratified holdout evaluation script.
- The current evaluation run used 225 training rows and 75 test rows (seed 42). It produced macro precision, recall, and F1 of 1.000, with confusion matrix `[[38, 0], [0, 37]]` for true/predicted classes `[benign, suspicious]`.
- **Interpretation:** these metrics apply only to a small, repetitive synthetic dataset. They are not evidence of real-world phishing or BEC detection performance.

### Safety, testing, and documentation

- Added URL defanging and text-only URL handling; the app does not fetch or resolve URLs.
- Attachment input is limited to metadata; attachment bytes are not uploaded or inspected.
- Email content is treated as untrusted text, not instructions. CSV exports protect against spreadsheet-formula injection.
- Documented privacy boundaries, limitations, architecture, fields, evaluation, and a short demonstration script.
- Validation run for this status report: `pytest -q` completed with **37 passed**; the evaluation script reproduced the metrics above.

## Remaining work, organized by presentation slide

| Slide | Status in repository | Work still needed before presenting |
|---|---|---|
| **1. Problem and target user** | The product is described as an educational email-triage tool for analysts or users reviewing suspicious email. | State the specific user persona and the BEC problem in plain language. Define the intended setting and what decisions the app supports. Avoid implying it blocks attacks or replaces security staff. |
| **2. Dataset and data pipeline** | Synthetic data generator, CSV schema, training script, and data card exist. | Show the flow from fictional records → validation/normalization → feature/text representation → training/evaluation. Explicitly label the data as synthetic. Explain class balance and leakage/template-similarity risks. A real dataset would require approval, consent, privacy controls, and labeling before use. |
| **3. Architecture diagram** | Architecture is documented in prose and implemented across the Streamlit app and `src/phishing_agent/`. | Create a clean visual diagram from user input through parser, features, rule/optional ML analysis, result, and CSV export. Mark local-only processing and the absent network/LLM/RAG components. |
| **4. Agent/RAG/ML workflow** | A deterministic analysis orchestrator, rules, and optional classical ML are implemented. | Explain that “agent” currently means deterministic orchestration, not autonomous tool use. Present the scoring modes and fallback behavior. Either explicitly scope RAG out or implement and evaluate a safe, sourced retrieval component before claiming RAG. |
| **5. Live or recorded demo** | The dashboard and a demo script with benign/suspicious examples and CSV workflow exist. | Run a clean rehearsal on the presentation machine. Demonstrate a benign and a suspicious example, explain evidence and uncertainty, then show batch CSV handling. Verify model availability beforehand and prepare a rules-only fallback/demo recording. Never use real confidential email in the demo. |
| **6. Evaluation and limitations** | A reproducible synthetic holdout script and limitations document exist; current tests pass. | Put the reproduced synthetic metrics on the slide with the dataset caveat directly beside them. Explain false positives/negatives and template overlap. Add independent, representative, authorized evaluation before making any operational performance claim. |
| **7. Business value and next steps** | Educational value and safe-use limitations are documented. | Tie value to analyst education and consistent triage, not proven loss prevention. Prioritize a threat-informed BEC test set, usability feedback, calibrated thresholds, and governance/privacy review. Define measurable next milestones and owners. |

### Cross-project priorities

1. **Presentation readiness:** confirm the target user and project boundaries; prepare the architecture graphic and rehearse the demo.
2. **BEC coverage:** verify the scenarios and rule evidence cover the team's intended BEC cases (for example, invoice/payment diversion and executive impersonation); record known gaps rather than treating generic phishing examples as comprehensive BEC coverage.
3. **Evaluation quality:** expand beyond repetitive templates; add a documented, independently designed test set and report per-class precision/recall, false-positive/false-negative examples, and threshold behavior. Use real email only with authorization and appropriate privacy controls.
4. **RAG decision:** if required by the rubric, define trusted source documents, retrieval/citation behavior, privacy boundaries, and prompt-injection tests before implementing it. Otherwise state plainly that RAG is not part of this version.
5. **Operational readiness (only if pursued):** establish deployment, access control, retention, audit, monitoring, incident-response ownership, and human-review requirements. The current app is educational and is not production-ready.

## Proposed division of work: five team members

Use the member numbers as placeholders and replace them with actual names. Each member has a primary ownership area; all five should review the final claims and demo safety.

| Team member / role | Primary ownership | Tasks to complete | Presentation contribution |
|---|---|---|---|
| **Member 1 — Product, user, and threat-model lead** | Problem definition, target user, requirements, and project boundaries. | Confirm the user persona and intended workflow; define BEC scenarios and success criteria; distinguish educational triage from a production control; coordinate final scope decisions, including whether RAG is required. | Lead Slide 1 and Slide 7; verify that value claims and next steps are evidence-based. |
| **Member 2 — Dataset and data-pipeline lead** | Synthetic data, schema, data generation, and data governance. | Explain the existing 300-row generator and fields; map ingestion and preprocessing; identify template overlap and missing BEC diversity; propose an authorized, privacy-reviewed plan for any future real data. | Lead Slide 2; clearly label current data as synthetic and describe its limitations. |
| **Member 3 — Detection and ML lead** | Feature extraction, heuristic scoring, model training, and model behavior. | Walk through rules and TF-IDF/logistic-regression modes; validate BEC-specific scenarios; identify feature gaps and threshold trade-offs; ensure model fallback and score/probability distinctions are explained. | Lead Slide 4; support Slide 3 and answer technical questions about the classifier. |
| **Member 4 — Application and demo lead** | Streamlit user experience, CSV workflow, demo environment, and run instructions. | Rehearse single and batch analysis; verify examples and model/rules fallback; prepare a recorded backup; make sure displayed examples and exports remain defanged and contain no confidential data. | Lead Slide 5; demonstrate the application and explain the user workflow. |
| **Member 5 — Evaluation, integration, and presentation lead** | Test execution, evaluation reporting, architecture diagram, and final slide consistency. | Re-run tests and holdout evaluation; prepare the architecture visual; distinguish measured synthetic results from real-world claims; collect limitations and milestone owners; assemble/review the seven slides. | Lead Slide 3 and Slide 6; integrate the final deck and verify evidence across all slides. |

### Suggested handoff and completion checks

- Agree on target user, BEC scope, and whether RAG is in scope before finalizing slides.
- Have each owner review the corresponding slide and implementation claims with one other teammate.
- Re-run `pytest -q` and `python scripts/evaluate_model.py` on the final presentation version.
- Rehearse the demo end-to-end, including a no-model fallback, and confirm the presentation contains no real email, credentials, or active links.
- Label all evaluation numbers as synthetic-data results and keep the limitations visible wherever the metrics are shown.

## Repository references

- [readme.md](./readme.md) — setup, application behavior, and run commands
- [docs/architecture.md](./docs/architecture.md) — current architecture
- [DATA_CARD.md](./DATA_CARD.md) — dataset source, fields, intended use, and limitations
- [docs/evaluation.md](./docs/evaluation.md) — holdout method and recorded result
- [docs/limitations.md](./docs/limitations.md) — false-positive, false-negative, and analyst guidance
- [demo/demo_script.md](./demo/demo_script.md) — demo sequence
- [SECURITY.md](./SECURITY.md) — security boundaries and safe-use guidance
