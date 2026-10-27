# Evaluation

Run `python scripts/evaluate_model.py` to reproduce the stratified 75/25 holdout (seed 42). The vectorizer is part of a scikit-learn pipeline and is fitted only on the training partition. The script prints macro precision, recall, F1, confusion matrix, and per-class metrics from the actual run.

## Recorded synthetic-data run

The project run used 225 training rows and 75 held-out rows. The observed macro precision, recall, and F1 were each **1.000**. With rows ordered true `[benign, suspicious]` and columns predicted `[benign, suspicious]`, the confusion matrix was:

```text
[[38, 0],
 [ 0, 37]]
```

This perfect result is **illustrative synthetic-data performance, not a production estimate**. The dataset is authored from a small set of repetitive patterns, so the random holdout can contain language closely related to training examples. The test partition does not represent future attackers, independent organizations, or real mail. Do not use these metrics to claim operational efficacy.

The deployment training script fits the optional final artifact on the complete synthetic dataset. The evaluation script trains its own model from scratch on its independent training split; it does not evaluate the full-data artifact.