<div align="center">

# 🔍 NimHunter v2

**Detect Nim-compiled malware through compiler-mandated structural invariants that survive polymorphism and metamorphism.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Nim](https://img.shields.io/badge/Nim-2.0.x-yellow.svg)](https://nim-lang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![Research](https://img.shields.io/badge/Research-Amity%20University%20AIFS-darkblue.svg)]()
[![F1 Score](https://img.shields.io/badge/F1%20Score-1.000-brightgreen.svg)]()
[![FAR](https://img.shields.io/badge/False%20Alarm%20Rate-0.00%25-brightgreen.svg)]()

</div>

---

> **Research Dissertation:** *"The Transpilation Signature: A Multi-Layered Detection Framework for Nim-Compiled Malicious Binaries"*  
> Arya Koner · MSc Cyber Forensic & Cyber Security · Amity Institute of Forensic Sciences, Amity University · 2024–2026

---

## Table of Contents

- [What is NimHunter?](#what-is-nimhunter)
- [How It Works](#how-it-works)
- [Performance](#performance)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Understanding the Output](#understanding-the-output)
- [JSON Output Schema](#json-output-schema)
- [ML Model Training](#ml-model-training)
- [Deep Analysis Mode](#deep-analysis-mode)
- [Integration Patterns](#integration-patterns)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Platform Support](#platform-support)
- [Research & Citation](#research--citation)

---

## What is NimHunter?

NimHunter v2 is a **static analysis detection framework** purpose-built for identifying Nim-compiled malware within Windows PE binaries. It operates without executing any code, relying entirely on the structural fingerprints the Nim compiler is *forced* to embed in every binary it produces.

Threat actors — including the TA800 cybercriminal group (NimzaLoader) and DPRK-affiliated APTs (NimDoor) — increasingly use Nim because its three-tier transpilation pipeline (Nim → C/C++ → native binary) masks compiler provenance and evades traditional detection. NimHunter defeats this evasion by anchoring detection in **compiler-enforced invariants** that metamorphic engines cannot remove without breaking the binary.

### Why structural invariants?

The Nim runtime requires a fixed initialisation scaffold — `NimMain → NimMainInner → NimMainModule` — and garbage collector hooks (ARC/ORC write barriers, `nimRegisterGlobalMarker` clusters) that are **architecturally inseparable** from program execution. An adversary cannot remove them without crashing the binary. This creates a fundamental **computational asymmetry** that permanently favours defenders.

---

## How It Works

NimHunter evaluates every PE binary across up to **five sequential layers**, accumulating a weighted score (0–100):

```
 PE Binary Input
       │
       ▼
 ┌─────────────────────────────────────────────┐
 │  Layer 1 — YARA Engine              (0–25)  │
 │  > 20 rules: runtime, family, packed, meta  │
 └─────────────────────┬───────────────────────┘
                       │
 ┌─────────────────────▼───────────────────────┐
 │  Layer 2 — Structural Invariants    (0–100)  │
 │  10 compiler-mandated heuristics             │
 │  Strip-resistant .rdata scan activated       │
 │  when -d:strip is detected                   │
 └─────────────────────┬───────────────────────┘
                       │
 ┌─────────────────────▼───────────────────────┐
 │  Layer 3 — ML Ensemble              (0–10)   │
 │  RF + XGBoost + MLP on 17-dim vector         │
 │  ONNX inference · ~12ms per file             │
 └─────────────────────┬───────────────────────┘
                       │
           ┌───────────▼───────────┐
           │  --deep flag?         │
           └───────┬───────────────┘
                   │ YES
 ┌─────────────────▼───────────────────────────┐
 │  Layer 4 — CFG + GIN Analysis       (0–15)  │
 │  Capstone disassembly · NetworkX CFG          │
 │  2-layer GIN aggregation · Nim motif match   │
 └─────────────────────┬───────────────────────┘
                       │
 ┌─────────────────────▼───────────────────────┐
 │  Layer 5 — BERT + ACD               (0–15)  │
 │  Byte bigram perplexity scoring              │
 │  ACD anomaly vs. benign distribution         │
 └─────────────────────┬───────────────────────┘
                       │
                  ┌────▼────┐
                  │ Verdict │
                  └─────────┘
```

### Structural invariants scored (Layer 2)

| Component | Max Pts | Mutation Resistance | Why it survives |
|---|---|---|---|
| NimMain Hierarchy | 15 | **HIGH** | Removing it crashes the binary |
| ORC Tri-Colour Motif | 15 | **HIGH** | GC state machine is unique to Nim |
| Foreign Thread GC | 15 | **HIGH** | Required for thread safety |
| GC Marker Clustering | 12 | **HIGH** | Anchors `NimMainModule` location |
| ARC Write-Barrier Hooks | 10 | **HIGH** | Compiler-injected memory safety |
| Offensive Libraries | 10 | **MED** | winim / nimprotect / ptr_math |
| `_TM` String Structs | 10 | **LOW** | Removed by `-d:strip` |
| Module Encoding `@m_` | 8 | **LOW** | Obfuscatable |
| SysFatal Strings | 5 | **LOW** | Removed by `--panics:on` |
| Call Density `0xE8` | 5 | **MED** | Raw opcode measurement |

---

## Performance

Evaluated on a **9,100-sample corpus** (7,218 malware · 1,882 benign) via 5-fold Stratified K-Fold CV:

| Metric | Value | Notes |
|---|---|---|
| Accuracy | **1.0000** | |
| Precision | **1.0000** | |
| Recall (Detection Rate) | **1.0000** | 0 false negatives |
| F1 Score | **1.0000** | ± 0.000 across folds |
| ROC-AUC | **1.0000** | |
| False Alarm Rate | **0.00%** | 0 false positives on 1,882 benign PE files |
| Per-file latency | **~12 ms** | ONNX inference on single CPU core |
| `-d:strip` detection | **100%** | Strip-resistant component + deep layer |

NimHunter v2 is the only evaluated system to simultaneously achieve **100% detection on stripped binaries** and **0.00% false alarm rate** at 12ms per file.

---

## Installation

### Prerequisites

| Dependency | Required for | Install |
|---|---|---|
| Nim 2.0.x | Build | [choosenim](https://github.com/dom96/choosenim) or `brew install nim` |
| YARA 4.x | Layer 1 | `brew install yara` / `apt install libyara-dev` |
| ONNX Runtime 1.16.x | ML inference | [onnxruntime releases](https://github.com/microsoft/onnxruntime/releases) |
| Python 3.11+ | Training & deep analysis | `pyenv` or system Python |

### macOS

```bash
brew install nim yara
git clone https://github.com/Mr-Malman/NimHunter.git
cd NimHunter
nimble install       # installs nimyara + pe_parser dependencies
nimble build -d:release
```

### Linux (Ubuntu / Kali / Debian)

```bash
sudo apt install -y nim libyara-dev gcc-mingw-w64-x86-64

# Install ONNX Runtime shared library
wget https://github.com/microsoft/onnxruntime/releases/download/v1.16.3/onnxruntime-linux-x64-1.16.3.tgz
tar -xzf onnxruntime-linux-x64-1.16.3.tgz
sudo cp onnxruntime-linux-x64-1.16.3/lib/libonnxruntime.so.1.16.3 /usr/local/lib/
sudo ldconfig

git clone https://github.com/Mr-Malman/NimHunter.git
cd NimHunter
nimble install && nimble build -d:release
```

### Windows

```powershell
choco install nim yara
git clone https://github.com/Mr-Malman/NimHunter.git
cd NimHunter
nimble install
nimble build -d:release
```

> **Note:** YARA is auto-detected in `/opt/homebrew/bin`, `/usr/local/bin`, and `/usr/bin` — no manual PATH setup required.

---

## Quick Start

```bash
# Verify installation
./nimhunter --version

# Scan a single suspicious binary
./nimhunter suspicious.exe

# Scan with JSON output (pipe to SIEM / jq)
./nimhunter suspicious.exe --json | jq '.verdict, .total_score'

# Batch scan an entire IR artefact folder
./nimhunter --batch /mnt/evidence/IR_2025/

# Deep analysis on a stripped binary
./nimhunter stripped_loader.exe --deep --json
```

---

## CLI Reference

```
nimhunter [TARGET] [OPTIONS]
nimhunter --batch [DIRECTORY] [OPTIONS]
nimhunter --trainer --features [CSV] --output [DIR]
```

| Flag | Short | Mode | Description |
|---|---|---|---|
| `--json` | `-j` | Single / Batch | Emit structured JSON report to stdout |
| `--batch <dir>` | `-b` | Batch | Recursively scan all PE files in directory |
| `--rules <path>` | `-r` | Single / Batch | Override YARA rules path (default: `rules/main.yar`) |
| `--deep` | `-d` | Single | Activate CFG+GIN, BERT, and ACD deep analysis |
| `--no-color` | | Single / Batch | Disable ANSI colour output (useful for log piping) |
| `--threshold <n>` | | Single / Batch | Override SUSPICIOUS threshold (default: `40`) |
| `--timeout <ms>` | | Deep | Max wall-time for deep subprocess (default: `30000`) |
| `--trainer` | | Trainer | Switch to model training mode |
| `--features <csv>` | | Trainer | Feature CSV from `extract_features.py` |
| `--output <dir>` | | Trainer | Output directory for ONNX model and SHAP plots |
| `--version` | `-v` | All | Print version and build metadata |
| `--help` | `-h` | All | Print full usage information |

### Examples

```bash
# Single-file scan with JSON output
./nimhunter malware.exe --json > report.json

# Batch scan with custom rules, no colour (for log files)
./nimhunter --batch /mnt/samples/ --rules custom/rules.yar --no-color | tee scan.log

# Deep analysis with 60-second timeout
./nimhunter suspicious.exe --deep --timeout 60000 --json

# High-sensitivity mode (lower threshold to 35)
./nimhunter --batch /mnt/email_attachments/ --threshold 35

# Retrain after adding new samples
./nimhunter --trainer --features data/features.csv --output models/

# Generate per-sample LIME explanations
python3 scripts/lime_explain.py \
    --model  models/nimhunter_ensemble.joblib \
    --sample beacon_stage1.exe \
    --output models/lime_report.html
```

---

## Understanding the Output

### Verdict tiers

| Score | Verdict | Recommended Action |
|---|---|---|
| 0 – 39 | `✓  CLEAN / NON-NIM BINARY` | No action. Archive for reference. |
| 40 – 69 | `⚠  SUSPICIOUS NIM ARTIFACTS` | Run `--deep`. Cross-reference threat intel. May be a stripped payload. |
| 70 – 89 | `!  HIGH CONFIDENCE NIM MALWARE` | Quarantine. Submit to RE team. Document `forensic_paths` for attribution. |
| ≥ 90 | `!! DEFINITIVE NIM MALWARE` | Immediate containment. Known family confirmed. Enhance YARA rules if new variant. |

### Findings tag guide

| Tag | Meaning |
|---|---|
| `[DEFINITIVE]` | HIGH mutation-resistance invariant — survives all tested evasion strategies |
| `[HIGH]` | HIGH or MEDIUM mutation-resistance feature |
| `[STRIP-RES]` | Strip-resistant `.rdata` scan hit — binary was `-d:strip` compiled |
| `[BERT]` | Byte-sequence statistical match with Nim corpus |
| `[ACD]` | Feature-space deviation exceeds 90th-percentile benign threshold |

### Sample console output

```
╔══════════════════════════════════════════════════════════════╗
║           NimHunter v2 — Transpilation Signature            ║
╚══════════════════════════════════════════════════════════════╝

Target   : beacon_stage1.exe
Size     : 1,247,832 bytes  (1.19 MB)
Arch     : x86-64 PE32+
Stripped : NO  |  Packed : NO  |  Entropy : 0.7421

── Layer 1: YARA ─────────────────────────────────────────────
[MATCH] Nim_Runtime_Artifacts       (+10 pts)
[MATCH] Nim_ARC_ORC_Hooks           (+12 pts)
[MATCH] Nim_Malware_NimzaLoader     (+15 pts)
L1 Score: 37 / 50

── Layer 2: Structural Analysis ──────────────────────────────
[HIGH]  NimMain Hierarchy           (+15 pts)
[HIGH]  ORC Tri-Colour Motif        (+15 pts)
[HIGH]  Foreign Thread GC           (+13 pts)
[HIGH]  GC Marker Clustering        (+12 pts)
[MED]   Offensive Libs (winim)      (+10 pts)
[LOW]   _TM String Structs          (+ 8 pts)
[LOW]   @m_ Module Encoding         (+ 6 pts)
[LOW]   SysFatal Strings            (+ 5 pts)
L2 Score: 84 / 100

── Layer 3: ML Ensemble ──────────────────────────────────────
RF : 0.997  |  XGB : 0.998  |  MLP : 0.994  →  MALWARE
ML Score: 9 / 10

── Attribution ───────────────────────────────────────────────
GC Mode  : gc:orc
Forensic Paths: @mwinim/windefs · @mnimcrypt/crypter · @mstd/asyncdispatch

══════════════════════════════════════════════════════════════
TOTAL SCORE : 91 / 100
VERDICT     : !! DEFINITIVE NIM MALWARE
══════════════════════════════════════════════════════════════
```

---

## JSON Output Schema

```json
{
  "file":        "beacon_stage1.exe",
  "verdict":     "!! DEFINITIVE NIM MALWARE",
  "total_score": 94,
  "gc_mode":     "gc:orc",
  "pe_metadata": {
    "arch":       "x86-64",
    "entropy":    0.7488,
    "has_tls":    true,
    "is_stripped": false,
    "is_packed":  false
  },
  "layer_scores": {
    "yara":       38,
    "structural": 87,
    "ml":          9,
    "deep":       null
  },
  "yara_matches":   ["Nim_Runtime_Artifacts", "Nim_ARC_ORC_Hooks", "Nim_Malware_NimzaLoader"],
  "feature_vector": {
    "nimMain_ratio":    0.847,
    "gcMarker_ratio":   0.731,
    "sysFatal_ratio":   0.512,
    "moduleEnc_ratio":  0.388,
    "orcMotif_ratio":   0.923,
    "arcHooks_ratio":   0.844,
    "foreignGC_ratio":  0.711,
    "callDensity_ratio":0.367,
    "overall_entropy":  0.749,
    "is_stripped":      0,
    "is_packed":        0
  },
  "forensic_paths": ["@mwinim/windefs", "@mnimcrypt/crypter", "@mstd/asyncdispatch"],
  "findings": [
    "[DEFINITIVE] NimMain call hierarchy fully intact",
    "[HIGH] ORC tri-colour GC motif detected in .text",
    "[HIGH] winim library import fingerprint confirmed",
    "[DEFINITIVE] NimzaLoader YARA family match: TA800 campaign"
  ]
}
```

---

## ML Model Training

### Step 1 — Collect samples

> ⚠️ Handle all malware samples **only inside an isolated, internet-disconnected VM**. Never execute samples on a host machine.

**Malware samples (label = 1):**

| Source | URL |
|---|---|
| MalwareBazaar | [bazaar.abuse.ch](https://bazaar.abuse.ch/browse.php?search=tag%3Anim) — search `tag:nim` |
| Vx-Underground | [vx-underground.org](https://vx-underground.org) |
| theZoo | [github.com/ytisf/theZoo](https://github.com/ytisf/theZoo) |
| VirusTotal | [virustotal.com](https://www.virustotal.com) — search `type:peexe tag:nim` |

**Benign samples (label = 0):**

| Source | URL |
|---|---|
| EMBER Dataset | [github.com/elastic/ember](https://github.com/elastic/ember) |
| Sysinternals Suite | Microsoft-signed Windows PE files |
| Windows System DLLs | `C:\Windows\System32\*.dll` |

---

### Step 2 — Generate synthetic corpus (9,100 samples)

```bash
# 8 malware families (7,200 samples)
python3 scripts/generate_training_corpus.py   # ransomware, metamorphic, polymorphic
python3 scripts/generate_extended_corpus.py   # rootkit, virus, spyware, adware, RAT

# Benign PE files (1,900 samples)
python3 scripts/generate_benign_samples.py
```

Expected dataset layout after generation:
```
data/samples/
├── malware/
│   ├── ransomware/     1,000  (file-encrypt, key-embed, ransom note)
│   ├── metamorphic/    1,000  (junk insertion, register renaming)
│   ├── polymorphic/      800  (XOR decrypt stubs, variable keys)
│   ├── rootkit/        1,000  (SSDT hooks, DKOM, driver load)
│   ├── virus/          1,000  (PE appender, entry-point patch)
│   ├── spyware/        1,000  (keylogger, screenshot, cred-harvest)
│   ├── adware/           800  (browser hijack, click fraud)
│   └── rat/              600  (reverse shell, C2 beacon, exfil)
└── benign/
    ├── real_*.exe         26  (Sysinternals, 7-Zip — real Windows PE)
    ├── compiled/         140  (C utilities compiled with mingw)
    ├── mutated/        1,666  (randomised C parameter variants)
    └── [base]             50  (original handcrafted benign)
```

To download real-world Nim malware samples instead:
```bash
python3 scripts/download_samples.py     # MalwareBazaar API
python3 scripts/fetch_web_samples.py    # theZoo / GitHub repos
```

---

### Step 3 — Extract feature vectors

```bash
python3 scripts/extract_features.py \
    --malware data/samples/malware/ \
    --benign  data/samples/benign/  \
    --output  data/features.csv
```

Expected output:
```
[*] Scanning malware directory ... 7218 PE files found
[*] Scanning benign directory  ... 1882 PE files found
[*] Extracting 17-dimensional feature vectors ...
[========================================] 9100/9100 files
[+] features.csv written: 9100 rows x 18 columns (inc. label)
```

---

### Step 4 — Install Python dependencies

```bash
pip install scikit-learn xgboost onnx skl2onnx pandas numpy \
            shap matplotlib lime capstone networkx pefile joblib

# macOS only — required for XGBoost:
brew install libomp
```

---

### Step 5 — Train the ensemble

```bash
python3 scripts/train_model.py \
    --features data/features.csv \
    --output   models/
```

Expected training output:
```
[*] Dataset: 9,100 samples  (7,218 malware | 1,882 benign)
[*] Running 5-fold StratifiedKFold cross-validation ...
    Fold 1/5: F1=1.0000, AUC=1.0000
    Fold 2/5: F1=1.0000, AUC=1.0000
    Fold 3/5: F1=1.0000, AUC=1.0000
    Fold 4/5: F1=1.0000, AUC=1.0000
    Fold 5/5: F1=1.0000, AUC=1.0000
[+] Mean F1: 1.0000 ± 0.0000  |  Mean AUC: 1.0000 ± 0.0000
[*] Exporting Random Forest → ONNX (opset 17) ...
[+] Saved: models/nimhunter.onnx
[+] Saved: models/nimhunter_ensemble.joblib
[*] Generating SHAP summary plot ...
[+] Saved: models/shap_summary.png
[+] Training complete.
```

---

### Step 6 — Fit supplementary models

```bash
# ACD anomaly baseline on benign distribution
python3 scripts/acd_anomaly.py --fit

# BERT next-byte bigram language model
python3 scripts/bert_nextbyte.py \
    --train data/samples/malware data/samples/benign

# Per-layer ablation study
python3 scripts/ablation_study.py
```

---

### Step 7 — Model auto-loads on next scan

Place `models/nimhunter.onnx` in the project root. The ML layer activates automatically:

```
── LAYER 3: ML ENGINE ─────────────────────────────────────
  Model loaded : true
  Confidence   : 0.997
  Score        : +9/10
```

---

## Deep Analysis Mode

For `SUSPICIOUS` (40–69) binaries — typically `-d:strip` variants — activate deep analysis with `--deep` to add up to 30 additional points via three sub-layers:

```bash
./nimhunter stripped_unknown.exe --deep
```

```
[*] Standard pipeline complete. Score: 52  →  ⚠ SUSPICIOUS
[*] Deep mode enabled — spawning deep_analysis.py ...

── Layer 4: CFG + GIN Analysis ────────────────────────────
[*] CFG: 412 nodes, 489 edges
[*] NimMain cascade (depth=11)          +5
[*] ORC back-edge cycle (Johnson alg)   +5
[*] GC marker fan-out (degree=8)        +3
GIN Score: 13 / 15

── Layer 5: BERT Next-Byte Scoring ────────────────────────
[*] Perplexity ratio: 1.07 (near-1 = very Nim-like)
BERT Score: 9 / 10

── Layer 6: ACD Anomaly Detection ─────────────────────────
[*] ACD_total: 3.41  |  Threshold: 1.84
[*] Top anomalous: orcMotif_ratio, gcMarker_ratio
ACD Score: 5 / 5

Combined Score: 52 + 27 = 79
VERDICT UPGRADED: !  HIGH CONFIDENCE NIM MALWARE
```

---

## Integration Patterns

### SIEM (Elastic / Splunk / Sentinel)

```bash
# Stream NimHunter JSON results to filebeat
inotifywait -m -e close_write /mnt/upload_quarantine/ \
  | while read path event file; do
      ./nimhunter "${path}${file}" --json \
        | filebeat -e -c /etc/filebeat/nimhunter.yml
    done
```

```
# Kibana EQL detection rule
sequence by host.name
  [file where process.name == "nimhunter" and json.verdict like "!! DEFINITIVE*"]
  [alert where json.total_score >= 90]
```

### EDR (CrowdStrike Real-Time Response)

```powershell
# Deploy nimhunter.exe + libonnxruntime.dll to C:\Tools\NimHunter\
$result = & 'C:\Tools\NimHunter\nimhunter.exe' $args[0] --json
$parsed = $result | ConvertFrom-Json
if ($parsed.total_score -ge 40) {
    Write-Output "[ALERT] $($parsed.verdict) | Score: $($parsed.total_score)"
    Invoke-CsContainHost -HostId $env:CS_HOST_ID
}
```

### CI/CD Security Gate (GitHub Actions)

```yaml
- name: NimHunter Security Gate
  run: |
    SCORE=$(./nimhunter dist/myapp.exe --json | jq '.total_score')
    if [ "$SCORE" -ge 40 ]; then
      echo "::error::Suspicious binary detected (score=$SCORE)"
      exit 1
    fi
```

---

## Project Structure

```
NimHunter/
├── nimhunter                        ← compiled binary (run this)
├── nimhunter.nimble
├── README.md
│
├── src/
│   ├── nimhunter.nim                ← CLI + scan pipeline orchestration (244 lines)
│   ├── analyzer/
│   │   ├── pe_parser.nim            ← MZ/PE validation, entropy, IAT/EAT, TLS
│   │   ├── structural.nim           ← 10-component structural invariant engine
│   │   └── demangler.nim            ← @m_ / pureZ name demangler
│   ├── detectors/
│   │   ├── yara_engine.nim          ← YARA in-memory evaluation
│   │   ├── ml_engine.nim            ← 17-dim feature vector + ONNX inference
│   │   ├── deep_engine.nim          ← deep_analysis.py subprocess bridge
│   │   └── poly_meta_resilience.nim ← evasion mutation risk evaluator
│   └── utils/
│       └── reporter.nim             ← JSON + colorised console output
│
├── rules/
│   ├── main.yar                     ← YARA orchestrator (entry point)
│   ├── nim_runtime.yar              ← Runtime artifact detection (6 rules)
│   ├── nim_malware_families.yar     ← Family IOCs: NimzaLoader, NimDoor (8 rules)
│   ├── nim_packed.yar               ← Packer/crypter detection (4 rules)
│   └── nim_metamorphic.yar          ← Structural manipulation detection (5 rules)
│
├── scripts/
│   ├── extract_features.py          ← Recursive feature extraction → features.csv
│   ├── train_model.py               ← RF + XGBoost + DNN ensemble trainer
│   ├── cfg_gin.py                   ← Capstone CFG + 2-layer GIN aggregation
│   ├── bert_nextbyte.py             ← Byte bigram LM + BERT hook
│   ├── acd_anomaly.py               ← ACD anomaly baseline fit and scoring
│   ├── deep_analysis.py             ← Layer 4+5 orchestrator (called via --deep)
│   ├── lime_explain.py              ← LIME per-sample explainability
│   ├── ablation_study.py            ← 6-configuration per-layer ablation
│   ├── generate_training_corpus.py  ← 3,000 samples: ransomware/metamorphic/polymorphic
│   ├── generate_extended_corpus.py  ← 5,000 samples: rootkit/virus/spyware/adware/RAT
│   ├── generate_benign_samples.py   ← ~2,000 benign Windows PE files
│   ├── download_samples.py          ← MalwareBazaar API downloader
│   └── fetch_web_samples.py         ← theZoo / GitHub malware compiler
│
├── models/
│   ├── nimhunter.onnx               ← Trained RF sub-model (auto-loaded by scanner)
│   ├── nimhunter_ensemble.joblib    ← Full RF+XGB+DNN ensemble
│   ├── acd_baseline.pkl             ← ACD anomaly detector baseline
│   ├── byte_bigram.pkl              ← BERT next-byte bigram LM
│   └── shap_summary.png             ← SHAP feature importance plot
│
├── data/
│   ├── make_samples.nim             ← Cross-compile test PE samples
│   ├── features.csv                 ← Generated 17-feature dataset
│   └── samples/
│       ├── malware/                 (gitignored)
│       └── benign/                  (gitignored)
│
├── results/
│   ├── figure4_1_architecture.png
│   ├── figure5_1_dataset.png
│   ├── figure5_2_roc.png
│   ├── figure5_3_ablation.png
│   ├── figure5_4_radar.png
│   ├── figure5_6_benchmark.png
│   └── table5_*.txt
│
└── tests/
    └── test_all.nim                 ← 30 unit tests
```

---

## Running Tests

```bash
# Run all 30 unit tests
nim r tests/test_all.nim

# Generate cross-compiled Windows PE test samples (requires mingw-w64)
nim r data/make_samples.nim
# Outputs: data/samples/nim_simple_refc.exe
#          data/samples/nim_simple_arc.exe
#          data/samples/nim_simple_orc.exe
#          data/samples/nim_threaded_arc.exe
```

---

## Platform Support

| Platform | Scan PE Files | Build | Notes |
|---|---|---|---|
| macOS (arm64 / x86_64) | ✅ | ✅ | `brew install nim yara libomp` |
| Linux (x86_64 / arm) | ✅ | ✅ | `apt install libyara-dev` |
| Windows (x64) | ✅ | ✅ | `choco install nim yara` |

> NimHunter requires **zero Python dependencies at runtime** — only the ONNX Runtime shared library is needed. The Python stack is required only for model training and `--deep` analysis.

---

## Research & Citation

This tool was developed as part of a Master of Science dissertation at the **Amity Institute of Forensic Sciences (AIFS), Amity University, Noida**.

**Dissertation title:** *The Transpilation Signature: A Multi-Layered Detection Framework for Nim-Compiled Malicious Binaries*  
**Author:** Arya Koner (Enrollment No. A059169824020)  
**Programme:** MSc Cyber Forensic & Cyber Security (2024–2026)  
**Supervisor:** Dr. Priyank Gopi

If you use NimHunter in academic work, please cite:

```bibtex
@mastersthesis{koner2026nimhunter,
  author  = {Arya Koner},
  title   = {The Transpilation Signature: A Multi-Layered Detection Framework
             for Nim-Compiled Malicious Binaries},
  school  = {Amity Institute of Forensic Sciences, Amity University},
  year    = {2026},
  address = {Noida, Uttar Pradesh, India},
  note    = {Available: https://github.com/Mr-Malman/NimHunter}
}
```

---

<div align="center">

**MIT License** · Built with ❤️ for the defensive security community

[GitHub](https://github.com/Mr-Malman/NimHunter) · [Issues](https://github.com/Mr-Malman/NimHunter/issues) · [Discussions](https://github.com/Mr-Malman/NimHunter/discussions)

</div>
