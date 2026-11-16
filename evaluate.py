"""Evaluate rules vs ML vs hybrid on a held-out split. Writes results/."""
import os
import pickle

import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from phishscope.analysis import FEATURE_COLS, extract_features, normalize
from phishscope.scorer import FLAG_AT, hybrid_score, ml_prob, rule_score, train_ml

if not os.path.exists("data/emails.csv"):
    import make_data  # noqa: F401
os.makedirs("results", exist_ok=True)
os.makedirs("models", exist_ok=True)

df = pd.read_csv("data/emails.csv").fillna("")
feats = [extract_features(normalize(r)) for r in df.to_dict("records")]
X = pd.DataFrame([[f[c] for c in FEATURE_COLS] for f in feats], columns=FEATURE_COLS)
y = (df["label"] == "phishing").astype(int)
idx_tr, idx_te = train_test_split(df.index, test_size=0.3, stratify=y, random_state=7)

model = train_ml(X.loc[idx_tr], y.loc[idx_tr])
with open("models/ml.pkl", "wb") as fh:
    pickle.dump(model, fh)

rows = []
for i in idx_te:
    rs = rule_score(feats[i])["score"]
    p = ml_prob(model, feats[i], FEATURE_COLS)
    rows.append({"id": df.id[i], "category": df.category[i], "truth": int(y[i]), "rules": rs,
                 "ml_prob": p, "hybrid": hybrid_score(rs, p), "subject": df.subject[i]})
res = pd.DataFrame(rows)
preds = {"Rules (score>=%d)" % FLAG_AT: (res.rules >= FLAG_AT), "ML (p>=0.5)": (res.ml_prob >= 0.5),
         "Hybrid (score>=%d)" % FLAG_AT: (res.hybrid >= FLAG_AT)}

lines = ["# PhishScope evaluation", f"Held-out test emails: {len(res)} ({res.truth.sum()} phishing)", "",
         "| Method | Precision | Recall | F1 | TN | FP | FN | TP |", "|---|---|---|---|---|---|---|---|"]
for name, p in preds.items():
    tn, fp, fn, tp = confusion_matrix(res.truth, p.astype(int)).ravel()
    lines.append(f"| {name} | {precision_score(res.truth, p):.3f} | {recall_score(res.truth, p):.3f} | "
                 f"{f1_score(res.truth, p):.3f} | {tn} | {fp} | {fn} | {tp} |")
    res[f"err_{name.split()[0]}"] = p.astype(int) != res.truth
res.to_csv("results/test_scores.csv", index=False)
errs = res[res.filter(like="err_").any(axis=1)]
errs.to_csv("results/errors.csv", index=False)
lines += ["", "Errors by category (any method):", errs.groupby(["category", "truth"]).size().to_string(),
          "", "Full per-email scores: results/test_scores.csv; errors: results/errors.csv"]
open("results/eval_report.md", "w").write("\n".join(lines))
print("\n".join(lines))
