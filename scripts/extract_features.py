#!/usr/bin/env python3
# scripts/extract_features.py — NimHunter Feature Extraction Pipeline
# Run: .venv/bin/python3.13 scripts/extract_features.py
#
# Recursively scans ALL PE files under:
#   data/samples/malware/**/*.exe  -> label=1 (Nim malware)
#   data/samples/benign/**/*.exe   -> label=0 (clean PE)
# Outputs: data/features.csv
#
# Run BEFORE train_model.py and ablation_study.py

import subprocess, json, re, csv, os, sys

NIMHUNTER = "./nimhunter"
if not os.path.exists(NIMHUNTER):
    print("[!] ./nimhunter binary not found. Run:  nimble build")
    sys.exit(1)

FEATURE_NAMES = [
    "nimMain_ratio", "gcMarker_ratio", "moduleEnc_ratio", "tmStrings_ratio",
    "sysFatal_ratio", "orcMotif_ratio", "arcHooks_ratio", "foreignGC_ratio",
    "callDensity_ratio", "overall_entropy", "tm_count_norm", "section_count_norm",
    "has_tls", "is_packed", "is_stripped", "gc_mode_norm", "offensive_libs_ratio",
]

env = {**os.environ, "PATH": "/opt/homebrew/bin:" + os.environ.get("PATH", "")}

def collect_exes(root: str) -> list:
    """Recursively collect all .exe/.dll files under root."""
    found = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if fn.lower().endswith((".exe", ".dll")):
                found.append(os.path.join(dirpath, fn))
    return sorted(found)

rows    = []
skipped = 0

CLASSES = [
    (1, "data/samples/malware"),
    (0, "data/samples/benign"),
]

for label, root in CLASSES:
    if not os.path.isdir(root):
        print(f"[!] Folder not found: {root}  (skipping label={label})")
        continue

    files = collect_exes(root)
    print(f"\n[*] label={label} -- found {len(files)} PE files under {root}/")

    for i, path in enumerate(files):
        if i % 500 == 0 and i > 0:
            print(f"    ... {i}/{len(files)} processed  ({len(rows)} rows so far)")

        try:
            r = subprocess.run(
                [NIMHUNTER, "--json", path],
                capture_output=True, text=True, env=env, timeout=30
            )
        except subprocess.TimeoutExpired:
            skipped += 1
            continue

        m = re.search(r"\{.*\}", r.stdout, re.DOTALL)
        if not m:
            skipped += 1
            continue
        try:
            d = json.loads(m.group())
        except json.JSONDecodeError:
            skipped += 1
            continue

        fv  = d.get("feature_vector", [])
        row = {n: round(v, 4) for n, v in zip(FEATURE_NAMES, fv)}
        row.update({
            "file":    path,
            "label":   label,
            "score":   d.get("total_score", 0),
            "verdict": d.get("verdict", ""),
            "gc_mode": d.get("gc_mode", ""),
        })
        rows.append(row)

print()
malware_n = sum(1 for r in rows if r["label"] == 1)
benign_n  = sum(1 for r in rows if r["label"] == 0)
print(f"[*] Extracted : {len(rows)} rows  ({malware_n} malware, {benign_n} benign)")
print(f"[*] Skipped   : {skipped}")
print(f"[*] Ratio     : {malware_n/max(benign_n,1):.1f}:1  (malware:benign)")

if len(rows) == 0:
    print("[!] No data. Check samples exist.")
    sys.exit(1)

if benign_n == 0 or malware_n == 0:
    print("[!] WARNING: Only one class found.")

os.makedirs("data", exist_ok=True)
fieldnames = ["file", "label", "score", "verdict", "gc_mode"] + FEATURE_NAMES
with open("data/features.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(rows)

print(f"\n[OK] data/features.csv -- {len(rows)} rows, {len(FEATURE_NAMES)} features")
print()
print("Next:")
print("  .venv/bin/python3.13 scripts/train_model.py")
print("  .venv/bin/python3.13 scripts/ablation_study.py")
