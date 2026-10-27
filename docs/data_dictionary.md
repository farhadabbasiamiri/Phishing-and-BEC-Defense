# Dataset and CSV field reference

See [DATA_CARD.md](../DATA_CARD.md) for generation, source assumptions, intended use, and limitations.

## Dataset fields

| Column | Type | Required for generated dataset | Use |
|---|---|---:|---|
| `id` | Text | Yes | Stable synthetic row ID; not used by the model |
| `sender` | Text | Yes | Fictional sender at a reserved `.example` domain |
| `reply_to` | Text | No | Optional fictional Reply-To |
| `subject` | Text | Yes | Synthetic subject |
| `body` | Text | Yes | Synthetic body with inert/defanged URLs |
| `auth_results` | Text | No | Synthetic supplied authentication observations |
| `attachment_metadata` | Text | No | Filename/extension only; no attachment bytes |
| `label` | `benign` / `suspicious` | Yes | Supervised target; excluded from model inputs |

## Batch CSV input

At least one of `subject` or `body` must be a column. Each row must contain non-empty subject or body content. All other fields are optional and default to empty text. Headers are case-insensitive; supported aliases and upload limits are documented in the [README](../README.md). `label` is ignored by inference. Malformed values are shown per row and do not invalidate other rows.