#!/usr/bin/env python3
# scripts/acd_anomaly.py — Aggregated Cumulative Deviation Anomaly Detection
# NimHunter v2 — Chapter 4 / 5.4 implementation
#
# Implements ACD (Aggregated Cumulative Deviation) as described in the thesis:
#
#   For each feature dimension d:
#     ACD_d(x) = |x_d - μ_d^(benign)| / σ_d^(benign)     ← normalized z-score deviation
#
#   ACD_total(x) = mean(ACD_d for d in 1..17)
#
#   anomaly_score = sigmoid(ACD_total - threshold) * 5     ← maps to 0-5 pts
#
# ACD tells us: "How different is this binary from benign PEs in feature space?"
# High ACD = statistically anomalous = strong signal it's not a normal PE.
#
# Usage:
#   # Fit baseline on benign samples from features.csv:
#   .venv/bin/python3.13 scripts/acd_anomaly.py --fit
#
#   # Score a feature vector (pass as JSON from nimhunter --json):
#   ./nimhunter --json sample.exe | python3 scripts/acd_anomaly.py --score -

import sys, os, json, pickle
import numpy as np

BASELINE_PATH = "models/acd_baseline.pkl"
FEATURES_CSV  = "data/features.csv"

FEATURE_NAMES = [
    "nimMain_ratio", "gcMarker_ratio", "moduleEnc_ratio", "tmStrings_ratio",
    "sysFatal_ratio", "orcMotif_ratio", "arcHooks_ratio", "foreignGC_ratio",
    "callDensity_ratio", "overall_entropy", "tm_count_norm", "section_count_norm",
    "has_tls", "is_packed", "is_stripped", "gc_mode_norm", "offensive_libs_ratio",
]


# ── Baseline Fitting ──────────────────────────────────────────────────────────

class ACDBaseline:
    """
    Fits and stores per-feature mean and std of the benign class.
    Used to compute ACD deviation scores for new samples.
    """
    def __init__(self):
        self.feature_means = None  # shape (17,)
        self.feature_stds  = None  # shape (17,)
        self.threshold     = 1.5   # ACD_total threshold for anomaly boundary
        self.fitted        = False

    def fit(self, X_benign: np.ndarray):
        """Fit baseline statistics on benign samples."""
        self.feature_means = X_benign.mean(axis=0)
        self.feature_stds  = X_benign.std(axis=0) + 1e-8  # avoid div by zero
        # Set threshold = 1.5 sigma (expected ACD for a sample at boundary)
        # Calibrate: fit ACD distribution on benign samples themselves
        acd_benign = self._raw_acd(X_benign)
        self.threshold = float(np.percentile(acd_benign, 90))  # 90th percentile of benign ACD
        self.fitted = True
        return self

    def _raw_acd(self, X: np.ndarray) -> np.ndarray:
        """Compute ACD_total for each row in X. Returns shape (n,)."""
        z = np.abs(X - self.feature_means) / self.feature_stds  # (n, 17)
        return z.mean(axis=1)  # (n,)

    def score(self, x: np.ndarray) -> dict:
        """
        Score a single sample.
        Returns: {acd_total, per_feature_deviations, anomaly_score (0-5), interpretation}
        """
        if not self.fitted:
            return {"error": "Baseline not fitted. Run: .venv/bin/python3.13 scripts/acd_anomaly.py --fit"}

        x = np.array(x[:len(FEATURE_NAMES)], dtype=np.float64)
        if len(x) < len(FEATURE_NAMES):
            x = np.concatenate([x, np.zeros(len(FEATURE_NAMES) - len(x))])

        # Per-feature z-score deviations
        z = np.abs(x - self.feature_means) / self.feature_stds

        # ACD total
        acd_total = float(z.mean())

        # Sigmoid mapping: sigmoid(ACD_total - threshold) * 5
        sig_input = acd_total - self.threshold
        anomaly_score = 5.0 / (1.0 + np.exp(-sig_input))
        anomaly_score = max(0.0, min(5.0, anomaly_score))

        # Per-feature breakdown (top deviating features)
        per_feature = {
            FEATURE_NAMES[i]: {
                "z_score": round(float(z[i]), 3),
                "sample_val": round(float(x[i]), 4),
                "benign_mean": round(float(self.feature_means[i]), 4),
            }
            for i in range(len(FEATURE_NAMES))
        }

        # Top 5 most anomalous features
        top5 = sorted(per_feature.items(), key=lambda kv: -kv[1]["z_score"])[:5]

        if acd_total > self.threshold * 1.5:
            interp = "HIGHLY ANOMALOUS — feature vector far from benign distribution"
        elif acd_total > self.threshold:
            interp = "ANOMALOUS — above benign 90th percentile"
        else:
            interp = "Within expected benign variation"

        return {
            "module":            "acd_anomaly",
            "acd_total":         round(acd_total, 4),
            "threshold_90pct":   round(self.threshold, 4),
            "anomaly_score":     round(anomaly_score, 2),
            "max_score":         5,
            "top_deviating_features": [
                {"feature": k, "z_score": v["z_score"],
                 "sample": v["sample_val"], "benign_mean": v["benign_mean"]}
                for k, v in top5
            ],
            "interpretation": interp,
        }

    def save(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({
                "means":     self.feature_means,
                "stds":      self.feature_stds,
                "threshold": self.threshold,
            }, f)

    def load(self, path: str):
        with open(path, "rb") as f:
            d = pickle.load(f)
        self.feature_means = d["means"]
        self.feature_stds  = d["stds"]
        self.threshold     = d["threshold"]
        self.fitted = True
        return self


# ── Fit from features.csv ─────────────────────────────────────────────────────

def fit_baseline():
    if not os.path.exists(FEATURES_CSV):
        print(f"[!] {FEATURES_CSV} not found. Run scripts/extract_features.py first.")
        sys.exit(1)

    try:
        import pandas as pd
    except ImportError:
        print("[!] pandas not installed")
        sys.exit(1)

    df = pd.read_csv(FEATURES_CSV)
    benign = df[df["label"] == 0]

    if len(benign) == 0:
        print("[!] No benign samples (label=0) in features.csv. Add benign PEs to data/samples/benign/")
        sys.exit(1)

    cols = [c for c in FEATURE_NAMES if c in df.columns]
    X_benign = benign[cols].fillna(0).values.astype(np.float64)

    baseline = ACDBaseline()
    baseline.fit(X_benign)
    baseline.save(BASELINE_PATH)

    print(f"[*] ACD Baseline fitted on {len(X_benign)} benign samples")
    print(f"    Threshold (90th percentile benign ACD): {baseline.threshold:.4f}")
    print(f"[✓] Saved → {BASELINE_PATH}")

    # Also print per-feature baseline stats for thesis Table
    print(f"\n{'Feature':<30} {'Benign Mean':>12} {'Benign Std':>12}")
    print("-" * 56)
    for i, name in enumerate(cols):
        print(f"{name:<30} {baseline.feature_means[i]:>12.4f} {baseline.feature_stds[i]:>12.4f}")


# ── Score from stdin / file ───────────────────────────────────────────────────

def score_from_input(src: str):
    if src == "-":
        raw = sys.stdin.read()
    else:
        raw = open(src).read()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print("[!] Could not parse JSON")
        sys.exit(1)

    fv = data.get("feature_vector", [])
    if not fv:
        print("[!] No 'feature_vector' in JSON. Run: ./nimhunter --json <file>")
        sys.exit(1)

    if not os.path.exists(BASELINE_PATH):
        print("[!] ACD baseline not fitted. Run: .venv/bin/python3.13 scripts/acd_anomaly.py --fit")
        sys.exit(1)

    baseline = ACDBaseline().load(BASELINE_PATH)
    result = baseline.score(fv)
    print(json.dumps(result, indent=2))


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or args[0] == "--fit":
        fit_baseline()
    elif args[0] == "--score":
        src = args[1] if len(args) > 1 else "-"
        score_from_input(src)
    else:
        # Assume it's a direct JSON file or nimhunter output
        score_from_input(args[0])
