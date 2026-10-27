# Data card: synthetic email triage examples

## Summary

`data/dummy_emails.csv` contains 300 reproducibly generated, fictional email records: 150 labelled `benign` and 150 labelled `suspicious`. Regenerate it with `python scripts/generate_data.py` (fixed seed: 42).

## Generation and source

All records are programmatically composed from templates written for this project. They are not sourced from real mail, people, organizations, credentials, or incident reports. People are fictional first-name placeholders; all email domains use the reserved `.example` namespace. URL examples use defanged `hxxp`/`hxxps` forms and reserved `.example` hosts. There are no active malicious links or payloads. No third-party dataset is redistributed; source and licensing assumptions are original educational synthetic content, with no independent legal review.

## Fields

| Field | Meaning |
|---|---|
| `id` | Stable synthetic record ID |
| `sender` | Fictional sender address at a reserved domain |
| `reply_to` | Optional fictional Reply-To address |
| `subject` | Synthetic subject text |
| `body` | Synthetic message text; URLs, if present, are defanged |
| `auth_results` | Synthetic, user-supplied-style SPF/DKIM/DMARC observations |
| `attachment_metadata` | Optional fictional attachment filename/extension only; no file content |
| `label` | `benign` or `suspicious`, used only as supervised-training target |

The model input builder selects sender, Reply-To, subject, body, authentication text, and attachment metadata explicitly; the label is not included in the feature text.

## Intended use

Coursework demonstrations of explainable triage, input validation, safe feature extraction, model training, and evaluation. Not intended for operational filtering, incident response conclusions, blocking decisions, or user-impacting decisions.

## Limitations and risks

The dataset is small, balanced by construction, repetitive, English-only, and drawn from a limited set of authored patterns. Some indicators are deliberately correlated with labels. It omits real headers, localization, benign urgency, nuanced business context, attacker diversity, evolving tactics, class imbalance, real attachment types/content, and independently verified authentication. Random holdouts can share template patterns across partitions. Metrics therefore measure behavior on these synthetic patterns only and may substantially overstate or understate performance on real email. False positives could flag legitimate requests; false negatives could miss phishing.

No URL reputation, DNS, sender authentication, or attachment inspection labels are present. Human review is always required. Do not add private or real email without appropriate consent, governance, and privacy protections.
