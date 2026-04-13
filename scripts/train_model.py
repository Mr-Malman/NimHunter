#!/usr/bin/env python3
# scripts/train_model.py — NimHunter ML engine trainer
# Run with: .venv/bin/python3.13 scripts/train_model.py
#           OR activate venv first: source .venv/bin/activate && python3 scripts/train_model.py

#
# Requirements:
#   pip install scikit-learn xgboost onnx skl2onnx pandas numpy shap matplotlib
#
# Usage:
#   1. Populate data/samples/malware/ with Nim PE malware  (label=1)
#      Populate data/samples/benign/  with clean PE files   (label=0)
#   2. Run: python3 scripts/extract_features.py   -> data/features.csv
#   3. Run: python3 scripts/train_model.py        -> models/nimhunter_rf.onnx
#
# Dataset sources:
#   Malware (label=1): bazaar.abuse.ch (tag:nim), vx-underground.org, theZoo
#   Benign  (label=0): EMBER dataset (github.com/elastic/ember), Windows system DLLs

import sys
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import f1_score, roc_auc_score, classification_report
from xgboost import XGBClassifier
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import shap
import joblib
import os

# ── FIX 1: All 17 features must match structural.nim / ml_engine.nim ──────────
FEATURE_NAMES = [
    "nimMain_ratio",      # NimMain hierarchy score (max 15)
    "gcMarker_ratio",     # nimRegisterGlobalMarker density (max 12)
    "moduleEnc_ratio",    # @m_ / pureZ encoding (max 8)
    "tmStrings_ratio",    # _TM string struct recovery (max 10)
    "sysFatal_ratio",     # sysFatal safety strings (max 5)
    "orcMotif_ratio",     # ORC tri-color GC motif (max 15)
    "arcHooks_ratio",     # ARC =copy/=destroy hooks (max 10)
    "foreignGC_ratio",    # setupForeignThreadGc (max 15)
    "callDensity_ratio",  # 0xE8 CALL opcode density (max 5)
    "overall_entropy",    # Shannon entropy of binary (0–8, norm to 0–1 by /8)
    "tm_count_norm",      # _TM string count / 20
    "section_count_norm", # PE section count / 10
    "has_tls",            # 1 if TLS section present
    "is_packed",          # 1 if high-entropy packing detected
    "is_stripped",        # 1 if symbol table stripped
    "gc_mode_norm",       # GC mode as int (0=unknown,1=refc,2=arc,3=orc) / 3
    "offensive_libs_ratio",  # winim/nimprotect/strenc library score (max 10)
]

assert len(FEATURE_NAMES) == 17, f"Expected 17 features, got {len(FEATURE_NAMES)}"

# ── Load dataset ───────────────────────────────────────────────────────────────
CSV_PATH = "data/features.csv"
if not os.path.exists(CSV_PATH):
    print(f"[!] Dataset not found: {CSV_PATH}")
    print("    Run scripts/extract_features.py first to build the dataset.")
    sys.exit(1)

df = pd.read_csv(CSV_PATH)

# Validate columns
missing = [f for f in FEATURE_NAMES if f not in df.columns]
if missing:
    print(f"[!] Missing columns in CSV: {missing}")
    sys.exit(1)

X = df[FEATURE_NAMES].values.astype(np.float32)
y = df["label"].values  # 0=benign, 1=nim_malware

print(f"[*] Dataset: {len(df)} samples  ({(y==1).sum()} malware, {(y==0).sum()} benign)")

if len(np.unique(y)) < 2:
    print("[!] Need both classes (label=0 and label=1). Add benign PEs to data/samples/benign/")
    sys.exit(1)

# ── Build classifiers ─────────────────────────────────────────────────────────
pos_weight = max((y==0).sum() / max((y==1).sum(), 1), 1.0)
min_class_size = int(min((y==0).sum(), (y==1).sum()))
# DNN early_stopping needs at least 2 samples per class in val split — disable for small sets
use_early_stop = min_class_size >= 4

rf  = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                              max_depth=12 if len(X) >= 20 else None,
                              random_state=42, n_jobs=-1)
xgb = XGBClassifier(scale_pos_weight=pos_weight, eval_metric="logloss",
                     n_estimators=100, max_depth=4, random_state=42, verbosity=0)
dnn = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=500,
                    random_state=42, early_stopping=use_early_stop)

ensemble = VotingClassifier(
    estimators=[("rf", rf), ("xgb", xgb), ("dnn", dnn)], voting="soft"
)

# ── Cross-validation (only if enough samples) ─────────────────────────────────
n_splits = min(5, min_class_size)
if n_splits >= 2:
    print(f"[*] Cross-validating with {n_splits}-fold StratifiedKFold ...")
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    scores = cross_validate(ensemble, X, y, cv=cv, scoring=["f1", "roc_auc"])
    print(f"    F1:  {scores['test_f1'].mean():.3f} +/- {scores['test_f1'].std():.3f}")
    print(f"    AUC: {scores['test_roc_auc'].mean():.3f}")
else:
    print(f"[!] Too few samples ({min_class_size}/class) for CV — fitting directly.")
    print("    Add more samples for reliable cross-validation.")

# Final fit on full dataset (cross_validate does NOT leave the model fitted)
print("[*] Fitting final model on full dataset...")
ensemble.fit(X, y)


# ── Final report ──────────────────────────────────────────────────────────────
from sklearn.metrics import classification_report
print("[*] Training classification report:")
print(classification_report(y, ensemble.predict(X), target_names=["benign", "nim_malware"]))


# ── FIX 2: SHAP on the RF sub-model only (VotingClassifier is not SHAP-compatible) ──
print("[*] Generating SHAP feature importance plot...")
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rf_fitted   = ensemble.named_estimators_["rf"]
    explainer   = shap.TreeExplainer(rf_fitted)
    shap_values = explainer.shap_values(X)
    sv = shap_values[1] if isinstance(shap_values, list) else shap_values
    shap.summary_plot(sv, X, feature_names=FEATURE_NAMES, show=False)
    plt.tight_layout()
    os.makedirs("models", exist_ok=True)
    plt.savefig("models/shap_summary.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("    SHAP summary → models/shap_summary.png")
except Exception as e:
    print(f"    [!] SHAP skipped: {e}")

# ── Save models ───────────────────────────────────────────────────────────────
os.makedirs("models", exist_ok=True)

joblib.dump(ensemble, "models/nimhunter_ensemble.joblib")
print("[✓] Ensemble saved → models/nimhunter_ensemble.joblib")

# ── FIX 3: Export only the RF sub-model to ONNX (skl2onnx doesn't support VotingClassifier) ──
print("[*] Exporting RandomForest sub-model to ONNX...")
try:
    rf_fitted    = ensemble.named_estimators_["rf"]
    initial_type = [("float_input", FloatTensorType([None, len(FEATURE_NAMES)]))]
    onnx_model   = convert_sklearn(rf_fitted, initial_types=initial_type,
                                   target_opset=17,
                                   options={id(rf_fitted): {"zipmap": False}})
    with open("models/nimhunter.onnx", "wb") as f:
        f.write(onnx_model.SerializeToString())
    print("[✓] ONNX model → models/nimhunter.onnx  (RF sub-model, auto-loaded by NimHunter)")
except Exception as e:
    print(f"[!] ONNX export failed: {e}")
    print("    Use models/nimhunter_ensemble.joblib for Python-side evaluation.")
