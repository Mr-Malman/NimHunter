#!/usr/bin/env python3
# scripts/ablation_study.py — NimHunter Chapter 5.3 Ablation Study
# Run: .venv/bin/python3.13 scripts/ablation_study.py
#
# Produces Table 5.3: Impact of each detection layer on F1 and AUC
# Requires: data/features.csv (run extract_features.py first)

import sys, os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, roc_auc_score, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_validate

CSV_PATH = "data/features.csv"
if not os.path.exists(CSV_PATH):
    print(f"[!] {CSV_PATH} not found. Run the feature extractor first.")
    sys.exit(1)

df = pd.read_csv(CSV_PATH)
y  = df["label"].values

# ── Feature groups matching dissertation layers ──────────────────────────────
YARA_PROXY   = ["score"]    # total YARA-weighted score as proxy for Layer 1

STRUCTURAL   = [            # Layer 2 — 10 structural invariants
    "nimMain_ratio", "gcMarker_ratio", "moduleEnc_ratio", "tmStrings_ratio",
    "sysFatal_ratio", "orcMotif_ratio", "arcHooks_ratio", "foreignGC_ratio",
    "callDensity_ratio", "offensive_libs_ratio",
]

PE_META      = [            # PE metadata features (header-level)
    "overall_entropy", "tm_count_norm", "section_count_norm",
    "has_tls", "is_packed", "is_stripped", "gc_mode_norm",
]

ALL_FEATURES = YARA_PROXY + STRUCTURAL + PE_META

# ── Ablation configurations ──────────────────────────────────────────────────
configs = [
    ("YARA-only (Layer 1 proxy)",      YARA_PROXY),
    ("Structural-only (Layer 2)",      STRUCTURAL),
    ("PE Metadata-only",               PE_META),
    ("YARA + Structural (L1+L2)",      YARA_PROXY + STRUCTURAL),
    ("Structural + PE Meta (L2+meta)", STRUCTURAL + PE_META),
    ("All features (L1+L2+ML meta)",   ALL_FEATURES),
]

min_class = int(min((y==0).sum(), (y==1).sum()))
n_splits  = min(5, min_class)
print(f"[*] Dataset: {len(df)} samples | {(y==1).sum()} malware, {(y==0).sum()} benign")
print(f"[*] Cross-validation: {n_splits}-fold StratifiedKFold\n")

print(f"{'Configuration':<40} {'F1':>7} {'±':>5} {'AUC':>7} {'FAR':>7}")
print("-" * 70)

results = []
for name, feats in configs:
    available = [f for f in feats if f in df.columns]
    if not available:
        print(f"{name:<40}  (no features available)")
        continue

    X = df[available].values.astype(np.float32)
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                 random_state=42, n_jobs=-1)

    if n_splits >= 2:
        cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
        scores = cross_validate(rf, X, y, cv=cv, scoring=["f1","roc_auc"])
        f1_mean  = scores["test_f1"].mean()
        f1_std   = scores["test_f1"].std()
        auc_mean = scores["test_roc_auc"].mean()
    else:
        f1_mean = f1_std = auc_mean = float("nan")

    # FAR on full fit
    rf.fit(X, y)
    y_pred = rf.predict(X)
    cm = confusion_matrix(y, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2,2) else (0,0,0,0)
    far = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"{name:<40} {f1_mean:>7.3f} {f1_std:>5.3f} {auc_mean:>7.3f} {far:>7.4f}")
    results.append({
        "configuration": name,
        "f1": round(f1_mean, 4),
        "f1_std": round(f1_std, 4),
        "auc": round(auc_mean, 4),
        "far": round(far, 4),
    })

print()
print("Table 5.3 complete — paste into dissertation Chapter 5.3")
print("For Figure 5.3: use the F1 and AUC columns as a grouped bar chart")

# Save results CSV for easy copy-paste into thesis
import csv
with open("models/ablation_results.csv","w",newline="") as f:
    w = csv.DictWriter(f, fieldnames=["configuration","f1","f1_std","auc","far"])
    w.writeheader()
    w.writerows(results)
print(f"[✓] Saved → models/ablation_results.csv")
