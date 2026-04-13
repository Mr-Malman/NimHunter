#!/usr/bin/env python3
# scripts/lime_explain.py — LIME Local Explainability for NimHunter
# NimHunter v2 — Chapter 4.5 / 5.5 implementation
#
# Generates a local, sample-specific explanation: which features pushed
# the verdict toward malware or benign for THIS specific binary.
#
# Output:
#   - JSON: {"contributions": [{"feature": "...", "weight": ...}, ...]}
#   - PNG:  models/lime_explanation_<basename>.png (bar chart)
#
# Usage:
#   .venv/bin/python3.13 scripts/lime_explain.py <feature_vector_json_or_pe_path>
#
#   The feature vector can come from nimhunter --json output OR be passed directly.

import sys, os, json
import numpy as np

try:
    import joblib
    JOBLIB_OK = True
except ImportError:
    JOBLIB_OK = False

try:
    from lime.lime_tabular import LimeTabularExplainer
    LIME_OK = True
except ImportError:
    LIME_OK = False

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    MPL_OK = True
except ImportError:
    MPL_OK = False

try:
    import pandas as pd
    PANDAS_OK = True
except ImportError:
    PANDAS_OK = False

MODEL_PATH   = "models/nimhunter_ensemble.joblib"
FEATURES_CSV = "data/features.csv"

FEATURE_NAMES = [
    "nimMain_ratio", "gcMarker_ratio", "moduleEnc_ratio", "tmStrings_ratio",
    "sysFatal_ratio", "orcMotif_ratio", "arcHooks_ratio", "foreignGC_ratio",
    "callDensity_ratio", "overall_entropy", "tm_count_norm", "section_count_norm",
    "has_tls", "is_packed", "is_stripped", "gc_mode_norm", "offensive_libs_ratio",
]

FEATURE_LABELS = [
    "NimMain hierarchy",     "GC marker clustering",   "Module encoding @m_",
    "TM string structs",     "SysFatal references",    "ORC tri-color motif",
    "ARC hooks",             "Foreign thread GC",      "Call density (0xE8)",
    "Section entropy",       "TM struct count (norm)", "Section count (norm)",
    "Has TLS section",       "Packed binary",          "Stripped symbols",
    "GC mode score",         "Offensive libraries",
]


def load_model():
    if not JOBLIB_OK:
        return None, "joblib not installed"
    if not os.path.exists(MODEL_PATH):
        return None, f"Model not found: {MODEL_PATH}. Run scripts/train_model.py first."
    return joblib.load(MODEL_PATH), None


def load_training_data():
    """Load background data for LIME from features.csv."""
    if not PANDAS_OK or not os.path.exists(FEATURES_CSV):
        # Return synthetic background (zeros) if no training data available
        return np.zeros((10, len(FEATURE_NAMES)))
    import pandas as pd
    df = pd.read_csv(FEATURES_CSV)
    cols = [c for c in FEATURE_NAMES if c in df.columns]
    return df[cols].fillna(0).values.astype(np.float32)


def explain(feature_vector: list, sample_name: str = "sample") -> dict:
    """
    Generate LIME explanation for a single sample.
    
    Args:
        feature_vector: list of 17 floats (from nimhunter --json output)
        sample_name:    used for output file naming
    
    Returns:
        dict with 'contributions', 'verdict', 'confidence', 'explanation_png'
    """
    result = {
        "module":          "lime_explain",
        "sample":          sample_name,
        "verdict":         None,
        "confidence":      None,
        "contributions":   [],
        "top_features":    [],
        "explanation_png": None,
        "error":           None,
    }

    if not LIME_OK:
        result["error"] = "lime not installed — run: .venv/bin/pip install lime"
        return result

    model, err = load_model()
    if model is None:
        result["error"] = err
        return result

    X_train = load_training_data()
    fv = np.array(feature_vector[:len(FEATURE_NAMES)], dtype=np.float32)

    # Pad if shorter than expected
    if len(fv) < len(FEATURE_NAMES):
        fv = np.concatenate([fv, np.zeros(len(FEATURE_NAMES) - len(fv))])

    # ── LIME Explainer ────────────────────────────────────────────────────────
    explainer = LimeTabularExplainer(
        training_data=X_train,
        feature_names=FEATURE_LABELS,
        class_names=["benign", "nim_malware"],
        mode="classification",
        discretize_continuous=True,
        random_state=42,
    )

    # Predict function: use the full ensemble
    def predict_proba(X):
        return model.predict_proba(X)

    explanation = explainer.explain_instance(
        data_row=fv,
        predict_fn=predict_proba,
        num_features=len(FEATURE_NAMES),
        num_samples=500,
        top_labels=2,
    )

    # Class 1 = nim_malware
    label = 1
    exp_list = explanation.as_list(label=label)
    proba    = explanation.predict_proba

    result["confidence"] = round(float(proba[label]), 3)
    result["verdict"]    = "nim_malware" if proba[label] > 0.5 else "benign"

    contributions = []
    for feat_cond, weight in exp_list:
        contributions.append({
            "feature_condition": feat_cond,
            "weight":  round(weight, 4),
            "direction": "→ malware" if weight > 0 else "→ benign",
        })
    result["contributions"] = contributions

    # Top 5 features
    result["top_features"] = [
        f"{c['feature_condition']} ({c['direction']})"
        for c in sorted(contributions, key=lambda x: abs(x["weight"]), reverse=True)[:5]
    ]

    # ── Save explanation plot ─────────────────────────────────────────────────
    if MPL_OK:
        os.makedirs("models", exist_ok=True)
        safe_name = "".join(c if c.isalnum() else "_" for c in sample_name)
        png_path  = f"models/lime_explanation_{safe_name}.png"

        fig, ax = plt.subplots(figsize=(10, 6))
        feats   = [c["feature_condition"] for c in contributions[:12]]
        weights = [c["weight"] for c in contributions[:12]]
        colors  = ["#e74c3c" if w > 0 else "#2ecc71" for w in weights]

        ax.barh(feats[::-1], weights[::-1], color=colors[::-1], edgecolor="white", height=0.7)
        ax.axvline(0, color="white", linewidth=0.8)
        ax.set_xlabel("LIME Weight (positive = towards nim_malware)", fontsize=10)
        ax.set_title(f"LIME Local Explanation — {sample_name}\n"
                     f"Verdict: {result['verdict']} (confidence: {result['confidence']:.1%})",
                     fontsize=11, fontweight="bold")
        ax.set_facecolor("#1a1a2e")
        fig.patch.set_facecolor("#0f0f1a")
        ax.tick_params(colors="white")
        ax.xaxis.label.set_color("white")
        ax.title.set_color("white")
        for spine in ax.spines.values():
            spine.set_edgecolor("#444")
        plt.tight_layout()
        plt.savefig(png_path, dpi=150, bbox_inches="tight", facecolor="#0f0f1a")
        plt.close()

        result["explanation_png"] = png_path
        print(f"[✓] LIME explanation → {png_path}")

    return result


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: .venv/bin/python3.13 scripts/lime_explain.py <nimhunter_json_output.json>")
        print("   OR: pipe nimhunter --json output:")
        print("       ./nimhunter --json sample.exe | python3 scripts/lime_explain.py /dev/stdin")
        sys.exit(1)

    # Read JSON from file or stdin
    src = sys.argv[1]
    if src == "/dev/stdin" or src == "-":
        raw = sys.stdin.read()
    else:
        raw = open(src).read()

    # nimhunter --json may emit log lines before the JSON block
    import re
    m = re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        print(f"[!] No JSON object found in input")
        sys.exit(1)

    try:
        data = json.loads(m.group())
    except json.JSONDecodeError:
        print(f"[!] Could not parse JSON input")
        sys.exit(1)

    fv = data.get("feature_vector", [])
    if not fv:
        print("[!] No 'feature_vector' field found in JSON. Run: ./nimhunter --json <file>")
        sys.exit(1)

    fname = os.path.basename(data.get("file", "sample"))
    result = explain(fv, sample_name=fname)
    print(json.dumps(result, indent=2))
