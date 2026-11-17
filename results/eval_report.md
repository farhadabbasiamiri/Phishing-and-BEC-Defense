# PhishScope evaluation
Held-out test emails: 150 (75 phishing)

| Method | Precision | Recall | F1 | TN | FP | FN | TP |
|---|---|---|---|---|---|---|---|
| Rules (score>=25) | 0.781 | 1.000 | 0.877 | 54 | 21 | 0 | 75 |
| ML (p>=0.5) | 1.000 | 1.000 | 1.000 | 75 | 0 | 0 | 75 |
| Hybrid (score>=25) | 1.000 | 1.000 | 1.000 | 75 | 0 | 0 | 75 |

Errors by category (any method):
category        truth
hard_it         0        10
hard_marketing  0        11

Full per-email scores: results/test_scores.csv; errors: results/errors.csv