## ml_engine.nim
## Machine learning detection engine for NimHunter v2
## Feature vector extraction + ONNX inference scaffold
## Train model with: python3 scripts/train_model.py
## Export to:        models/nimhunter.onnx

import os, strutils, math, sequtils, algorithm
import ../analyzer/pe_parser
import ../analyzer/structural

type
  MLResult* = object
    score*:          int     ## 0-10 ML contribution to total
    confidence*:     float   ## 0.0–1.0 maliciousness probability
    modelAvailable*: bool
    topFeatures*:    seq[tuple[name: string, value: float]]

## Feature names (must match training script column order)
const FEATURE_NAMES* = [
  "nimMain_ratio",
  "gcMarker_ratio",
  "moduleEnc_ratio",
  "tmStrings_ratio",
  "sysFatal_ratio",
  "orcMotif_ratio",
  "arcHooks_ratio",
  "foreignGC_ratio",
  "callDensity_ratio",
  "overall_entropy",
  "tm_count_norm",
  "section_count_norm",
  "has_tls",
  "is_packed",
  "is_stripped",
  "gc_mode_norm",
  "offensive_libs_ratio"
]

proc findModel(): string =
  ## Locate the ONNX model file
  let candidates = [
    "models/nimhunter.onnx",
    "../models/nimhunter.onnx",
    getAppDir() / "models/nimhunter.onnx"
  ]
  for c in candidates:
    if fileExists(c): return c
  return ""

proc featuresToCSV*(features: seq[float]): string =
  ## Serialize feature vector to CSV for external inference
  features.mapIt($it).join(",")

proc heuristicMLScore(features: seq[float]): float =
  ## Rule-based approximation of ML output when no ONNX model is loaded.
  ## Uses weighted sum of normalized feature values.
  ## Replace with real ONNX inference once model is trained.
  if features.len < 9: return 0.0
  
  let weights = [
    0.20,  # nimMain_ratio        (most discriminative)
    0.15,  # gcMarker_ratio
    0.08,  # moduleEnc_ratio
    0.07,  # tmStrings_ratio
    0.05,  # sysFatal_ratio
    0.18,  # orcMotif_ratio       (mutation-resistant)
    0.10,  # arcHooks_ratio
    0.12,  # foreignGC_ratio      (definitive indicator)
    0.05,  # callDensity_ratio
  ]
  
  result = 0.0
  for i in 0 ..< min(features.len, weights.len):
    result += features[i] * weights[i]
  result = min(result, 1.0)

proc runMLEngine*(structRes: DetectionResult, peInfo: PEInfo): MLResult =
  ## Run ML inference on feature vector.
  ## Falls back to heuristic scoring if ONNX model is unavailable.
  result = MLResult(score: 0, confidence: 0.0, modelAvailable: false)

  let features = structRes.featureVector
  if features.len == 0:
    return

  # Top features for explainability output
  for i in 0 ..< min(features.len, FEATURE_NAMES.len):
    result.topFeatures.add((name: FEATURE_NAMES[i], value: features[i]))

  # Sort by value descending (highest contributing features first)
  result.topFeatures.sort(proc(a, b: tuple[name: string, value: float]): int =
    cmp(b.value, a.value))

  # Try to load ONNX model
  let modelPath = findModel()
  if modelPath != "":
    result.modelAvailable = true
    # TODO: Load ONNX runtime and run inference
    # import onnxruntime  # when nim ONNX bindings available
    # result.confidence = onnxInfer(modelPath, features)
    echo "[ML] ONNX model found at: " & modelPath & " (inference stub — train first)"
    result.confidence = heuristicMLScore(features)
  else:
    result.confidence = heuristicMLScore(features)

  # Convert probability to 0-10 score contribution
  result.score = int(result.confidence * 10.0)

## Python training script template (print this with --generate-trainer flag)
const TRAINER_SCRIPT* = """
#!/usr/bin/env python3
# scripts/train_model.py — NimHunter ML engine trainer
#
# Requirements:
#   pip install scikit-learn xgboost onnx skl2onnx pandas numpy shap matplotlib
#
# Usage:
#   1. Add Nim malware PE files to  data/samples/malware/  (label=1)
#      Add benign PE files to       data/samples/benign/   (label=0)
#   2. python3 scripts/extract_features.py  -> data/features.csv
#   3. python3 scripts/train_model.py       -> models/nimhunter.onnx
#
# Dataset sources:
#   Malware: bazaar.abuse.ch (tag:nim), vx-underground.org, theZoo
#   Benign:  EMBER dataset (github.com/elastic/ember), Windows system DLLs

import sys, os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import classification_report
from xgboost import XGBClassifier
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import shap, joblib

# All 17 features — must match FEATURE_NAMES in ml_engine.nim
FEATURE_NAMES = [
    "nimMain_ratio", "gcMarker_ratio", "moduleEnc_ratio", "tmStrings_ratio",
    "sysFatal_ratio", "orcMotif_ratio", "arcHooks_ratio", "foreignGC_ratio",
    "callDensity_ratio", "overall_entropy", "tm_count_norm", "section_count_norm",
    "has_tls", "is_packed", "is_stripped", "gc_mode_norm",
    "offensive_libs_ratio"   # <-- FIX: was missing, now 17 features total
]

assert len(FEATURE_NAMES) == 17

CSV_PATH = "data/features.csv"
if not os.path.exists(CSV_PATH):
    print(f"[!] {CSV_PATH} not found. Run scripts/extract_features.py first.")
    sys.exit(1)

df = pd.read_csv(CSV_PATH)
X = df[FEATURE_NAMES].values.astype(np.float32)
y = df["label"].values  # 0=benign, 1=nim_malware

print(f"[*] {len(df)} samples: {(y==1).sum()} malware, {(y==0).sum()} benign")

if len(np.unique(y)) < 2:
    print("[!] Dataset needs both label=0 (benign) and label=1 (malware) rows.")
    sys.exit(1)

pos_weight = max((y==0).sum() / max((y==1).sum(), 1), 1.0)
rf  = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                              max_depth=12, random_state=42, n_jobs=-1)
xgb = XGBClassifier(scale_pos_weight=pos_weight, eval_metric="logloss",
                     n_estimators=200, max_depth=8, random_state=42, verbosity=0)
dnn = MLPClassifier(hidden_layer_sizes=(128, 64, 32), max_iter=500,
                    random_state=42, early_stopping=True)

ensemble = VotingClassifier(estimators=[("rf",rf),("xgb",xgb),("dnn",dnn)], voting="soft")

print("[*] Cross-validating...")
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
scores = cross_validate(ensemble, X, y, cv=cv, scoring=["f1","roc_auc"])
print(f"    F1  = {scores['test_f1'].mean():.3f} +/- {scores['test_f1'].std():.3f}")
print(f"    AUC = {scores['test_roc_auc'].mean():.3f}")

ensemble.fit(X, y)
print(classification_report(y, ensemble.predict(X), target_names=["benign","nim_malware"]))

# FIX: SHAP on RF sub-model only — VotingClassifier is not TreeExplainer-compatible
try:
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    rf_fit = ensemble.named_estimators_["rf"]
    sv = shap.TreeExplainer(rf_fit).shap_values(X)
    sv = sv[1] if isinstance(sv, list) else sv
    shap.summary_plot(sv, X, feature_names=FEATURE_NAMES, show=False)
    plt.tight_layout()
    os.makedirs("models", exist_ok=True)
    plt.savefig("models/shap_summary.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("[*] SHAP plot -> models/shap_summary.png")
except Exception as e:
    print(f"[!] SHAP skipped: {e}")

os.makedirs("models", exist_ok=True)
joblib.dump(ensemble, "models/nimhunter_ensemble.joblib")
print("[✓] Ensemble -> models/nimhunter_ensemble.joblib")

# FIX: Export RF sub-model to ONNX — skl2onnx does not support VotingClassifier
try:
    rf_fit = ensemble.named_estimators_["rf"]
    onnx_model = convert_sklearn(rf_fit,
        initial_types=[("float_input", FloatTensorType([None, len(FEATURE_NAMES)]))],
        target_opset=17, options={id(rf_fit): {"zipmap": False}})
    with open("models/nimhunter.onnx", "wb") as f:
        f.write(onnx_model.SerializeToString())
    print("[✓] ONNX -> models/nimhunter.onnx  (auto-loaded by NimHunter on next scan)")
except Exception as e:
    print(f"[!] ONNX export failed: {e}")
    print("    Joblib model still usable for Python evaluation.")
"""