# NimHunter v2

> **Detect Nim-compiled malware through compiler-mandated structural invariants that survive polymorphism and metamorphism.**

**Research Thesis:** *"The Transpilation Signature: A Multi-Layered Detection Framework for Nim-Compiled Malicious Binaries"* — AIFS, Amity University

---

## Installation

### macOS
```bash
brew install nim yara mingw-w64 libomp
git clone https://github.com/Mr-Malman/NimHunter.git
cd NimHunter
nimble build
```

### Kali Linux / Debian
```bash
sudo apt install nim yara gcc-mingw-w64-x86-64 libyara-dev
nimble build
```

### Windows
```powershell
choco install nim yara
nimble build
```

> **Note:** YARA auto-detected in `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin` — no PATH setup needed.

---

## Commands

### Scan a single file
```bash
./nimhunter <file.exe>
./nimhunter data/samples/malware/nim_malware.exe
```

### Batch scan a directory
```bash
./nimhunter --batch=<directory>
./nimhunter --batch=data/samples/malware
```

### JSON output (SIEM / pipeline integration)
```bash
./nimhunter --json <file.exe>
./nimhunter --json data/samples/malware/sample.exe | python3 -m json.tool
```

### Custom YARA rules
```bash
./nimhunter --rules=<path/to/main.yar> <file.exe>
./nimhunter --rules=custom/rules.yar data/samples/malware/sample.exe
```

### Disable color output
```bash
./nimhunter --no-color <file.exe> > report.txt
```

### Export ML training script
```bash
./nimhunter --generate-trainer > scripts/train_model.py
```

### Other flags
```bash
./nimhunter --version
./nimhunter --help
```

---

## Running Tests

### Unit Tests (30 tests)
```bash
nim r tests/test_all.nim
```

### Generate cross-compiled Windows PE test samples
```bash
nim r data/make_samples.nim
# Requires: brew install mingw-w64
# Outputs:  data/samples/nim_simple_refc.exe
#           data/samples/nim_simple_arc.exe
#           data/samples/nim_simple_orc.exe
#           data/samples/nim_threaded_arc.exe
```

---

## Understanding the Output

NimHunter scores every binary **0–100** across 4 layers:

| Layer | Max | Signal |
|---|---|---|
| Layer 1 — YARA | 25 pts | Static signatures, known malware strings |
| Layer 2 — Structural | 75 pts | Compiler-mandated invariants (mutation-resistant) |
| Layer 3 — Poly/Meta | Info | Evasion risk rating |
| Layer 4 — ML | 10 pts | 17-dimensional feature vector ensemble |

### Verdict thresholds

| Score | Verdict |
|---|---|
| 0 – 39 | `[✓] CLEAN OR NON-NIM BINARY` |
| 40 – 69 | `[?] SUSPICIOUS NIM ARTIFACTS DETECTED` |
| 70 – 89 | `[!!!] HIGH CONFIDENCE NIM MALWARE` |
| 90 – 100 | `[!!!] DEFINITIVE NIM MALWARE — STRUCTURAL INVARIANTS CONFIRMED` |

### Structural invariants (Layer 2)

| Component | Max Pts | Mutation Resistance |
|---|---|---|
| NimMain Hierarchy | 15 | HIGH — cannot be removed without crashing |
| ORC Tri-Color Motif | 15 | HIGH — unique GC state machine |
| Foreign Thread GC | 15 | HIGH — definitive Nim injection indicator |
| GC Marker Clustering | 12 | HIGH — anchors `NimMainModule` location |
| ARC Hooks | 10 | HIGH — compiler-injected memory hooks |
| Offensive Libraries | 10 | MED — winim / nimprotect / strenc / ptr_math |
| `_TM` String Structs | 10 | LOW — removable with `-d:strip` |
| Module Encoding `@m_` | 8 | LOW — can be obfuscated |
| SysFatal Strings | 5 | LOW — removable with `--panics:on` |
| Call Density `0xE8` | 5 | MED — raw opcode measurement |

---

## ML Model Training

### Step 1 — Collect samples

**Malware samples (label=1):**

| Source | URL |
|---|---|
| MalwareBazaar | [bazaar.abuse.ch](https://bazaar.abuse.ch/browse.php?search=tag%3Anim) — search `tag:nim` |
| Vx-Underground | [vx-underground.org](https://vx-underground.org) |
| theZoo | [github.com/ytisf/theZoo](https://github.com/ytisf/theZoo) |
| VirusTotal | [virustotal.com](https://www.virustotal.com) — search `type:peexe tag:nim` |

**Benign samples (label=0):**

| Source | URL |
|---|---|
| EMBER Dataset | [github.com/elastic/ember](https://github.com/elastic/ember) |
| Windows System DLLs | `C:\Windows\System32\*.dll` |

> ⚠️ Handle malware only inside an **isolated VM**. Never execute samples.

### Step 2 — Generate synthetic training corpus (9,100 samples)

**Option A — Auto-generate 8 malware families (3,000 + 5,000 samples):**
```bash
# Ransomware, Metamorphic, Polymorphic (1,000 each)
python3 scripts/generate_training_corpus.py

# Rootkit, Virus, Spyware, Adware, RAT (1,000 each)
python3 scripts/generate_extended_corpus.py

# 2,000 benign C utilities + real Windows PE
python3 scripts/generate_benign_samples.py
```

**Option B — Download real-world Nim malware:**
```bash
python3 scripts/download_samples.py        # MalwareBazaar API
python3 scripts/fetch_web_samples.py       # theZoo / GitHub repos
```

**Dataset structure after generation:**
```
data/
└── samples/
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
        ├── [base]            50   (original handcrafted benign)
        ├── real_*.exe        26   (Sysinternals, 7-Zip — real Windows PE)
        ├── compiled/        140   (C utilities compiled with mingw)
        └── mutated/       1,666   (randomised C parameter variants)
```

### Step 3 — Generate feature vectors
```bash
python3 << 'EOF'
import subprocess, json, re, csv, os, glob

NAMES = [
    'nimMain_ratio','gcMarker_ratio','moduleEnc_ratio','tmStrings_ratio',
    'sysFatal_ratio','orcMotif_ratio','arcHooks_ratio','foreignGC_ratio',
    'callDensity_ratio','overall_entropy','tm_count_norm','section_count_norm',
    'has_tls','is_packed','is_stripped','gc_mode_norm','offensive_libs_ratio'
]
env = {**os.environ, "PATH": "/opt/homebrew/bin:" + os.environ.get("PATH","")}
rows = []

for label, folder in [(1, "data/samples/malware"), (0, "data/samples/benign")]:
    for path in glob.glob(folder + "/*.exe"):
        r = subprocess.run(["./nimhunter","--json",path], capture_output=True, text=True, env=env)
        m = re.search(r'\{.*\}', r.stdout, re.DOTALL)
        if not m: continue
        d = json.loads(m.group())
        fv = d.get("feature_vector", [])
        row = {n: round(v,4) for n,v in zip(NAMES, fv)}
        row.update({"file": path, "label": label, "score": d.get("total_score",0)})
        rows.append(row)

with open("data/features.csv","w",newline="") as f:
    w = csv.DictWriter(f, fieldnames=["file","label","score"]+NAMES)
    w.writeheader()
    w.writerows(rows)
print(f"[✓] {len(rows)} samples → data/features.csv")
EOF
```

### Step 4 — Install Python dependencies
```bash
pip install scikit-learn xgboost onnx skl2onnx pandas numpy shap matplotlib
# macOS only — required for XGBoost:
brew install libomp
```

### Step 5 — Full training pipeline
```bash
# Extract features from all 9,100 samples (recursive scan)
python3 scripts/extract_features.py

# Train RF + XGB + DNN ensemble
python3 scripts/train_model.py

# Fit ACD anomaly baseline on benign distribution
python3 scripts/acd_anomaly.py --fit

# Train BERT next-byte bigram language model
python3 scripts/bert_nextbyte.py \
    --train data/samples/malware data/samples/benign

# Run ablation study
python3 scripts/ablation_study.py
```

Expected output (9,100-sample corpus):
```
[*] Dataset: 9,100 samples  (7,218 malware | 1,882 benign)
[*] Cross-validating with 5-fold StratifiedKFold ...
    F1:  1.000 +/- 0.000
    AUC: 1.000
[*] Training classification report:
              precision    recall  f1-score   support
      benign       1.00      1.00      1.00      1882
 nim_malware       1.00      1.00      1.00      7218
    accuracy                           1.00      9100
[*] SHAP plot → models/shap_summary.png
[✓] Ensemble saved → models/nimhunter_ensemble.joblib
[✓] ONNX model   → models/nimhunter.onnx

[*] ACD Baseline fitted on 1,882 benign samples
    Threshold (90th percentile): 0.0332
[✓] Saved → models/acd_baseline.pkl

[*] BERT bigram: Nim perplexity=12.5 | Benign=50.6  (4.0x separation)
[✓] Saved → models/byte_bigram.pkl
```

### Step 6 — Model auto-loads on next scan
Place `models/nimhunter.onnx` in the project root. Next scan shows:
```
── LAYER 4: ML ENGINE ─────────────────────────
  Model loaded : true
  Confidence   : 0.923
  Score        : +9/10
```

---

## Project Structure

```
NimHunter/
├── nimhunter                    ← compiled binary (run this)
├── nimhunter.nimble
├── README.md
├── rules/
│   ├── main.yar                 ← YARA orchestrator (entry point)
│   ├── nim_arc.yar
│   ├── nim_orc.yar
│   ├── nim_evasion.yar
│   ├── nim_families.yar
│   └── signatures/              ← per-family rules
├── src/
│   ├── nimhunter.nim            ← CLI + orchestration pipeline
│   ├── analyzer/
│   │   ├── pe_parser.nim        ← PE metadata, entropy, imports
│   │   ├── structural.nim       ← 10-component invariant engine
│   │   └── demangler.nim        ← @m_ / pureZ path decoder
│   ├── detectors/
│   │   ├── yara_engine.nim      ← YARA subprocess wrapper (auto-finds binary)
│   │   ├── poly_meta_resilience.nim  ← evasion risk evaluator
│   │   └── ml_engine.nim        ← feature vector + ONNX inference
│   └── utils/
│       └── reporter.nim         ← console + JSON output
├── tests/
│   └── test_all.nim             ← 30 unit tests
├── data/
│   ├── make_samples.nim         ← cross-compile test PEs
│   └── samples/
│       ├── malware/             ← your malware samples (gitignored)
│       └── benign/              ← your benign samples (gitignored)
├── scripts/
│   ├── extract_features.py      ← recursive feature extraction → data/features.csv
│   ├── train_model.py           ← RF+XGB+DNN ensemble trainer
│   ├── ablation_study.py        ← per-layer ablation (Table 5.3)
│   ├── acd_anomaly.py           ← ACD anomaly baseline fit
│   ├── bert_nextbyte.py         ← BERT bigram language model
│   ├── cfg_gin.py               ← CFG extraction + GIN scoring
│   ├── deep_analysis.py         ← Layer 5 orchestrator
│   ├── lime_explain.py          ← LIME feature explainability
│   ├── generate_training_corpus.py  ← 3,000 ransomware/metamorphic/polymorphic
│   ├── generate_extended_corpus.py  ← 5,000 rootkit/virus/spyware/adware/RAT
│   ├── generate_benign_samples.py   ← 2,000 benign Windows PE files
│   ├── download_samples.py      ← MalwareBazaar bulk downloader
│   └── fetch_web_samples.py     ← theZoo / GitHub repo compiler
├── models/
│   ├── nimhunter.onnx           ← trained RF sub-model (auto-loaded by scanner)
│   ├── nimhunter_ensemble.joblib← full RF+XGB+DNN ensemble
│   ├── acd_baseline.pkl         ← ACD anomaly detector baseline
│   ├── byte_bigram.pkl          ← BERT next-byte language model
│   └── shap_summary.png         ← SHAP feature importance plot
├── results/
│   ├── table5_2_performance.txt ← Main metrics (9,100 samples)
│   ├── table5_3_ablation.txt    ← Per-layer ablation study
│   ├── table5_4_metamorphic.txt ← Metamorphic/evasion robustness
│   ├── table5_5_benchmark.txt   ← Comparison vs. baselines
│   ├── table5_deep_stripped.txt ← Strip-resistant deep analysis
│   ├── figure5_2_roc.png        ← ROC curve
│   └── figure5_5_shap.png       ← SHAP summary
└── libs/
    └── nimyara/                 ← YARA C-binding (optional)
```

---

## JSON Output Format

```json
{
  "file": "data/samples/malware/nim_refc.exe",
  "verdict": "SUSPICIOUS NIM ARTIFACTS DETECTED",
  "total_score": 53,
  "gc_mode": "gc:refc",
  "pe_metadata": {
    "arch": "x64", "entropy": 6.03, "has_tls": true, "stripped": false
  },
  "component_scores": {
    "yara_layer": {"score": 18, "matches": 1},
    "structural_layer": {
      "nim_main_hierarchy": {"score": 15, "max": 15},
      "gc_marker_clustering": {"score": 5, "max": 12},
      "foreign_thread_gc": {"score": 8, "max": 15},
      "sys_fatal": {"score": 5, "max": 5},
      "total": 35
    },
    "ml_layer": {"score": 3, "confidence": 0.397}
  },
  "yara_rules_matched": ["Nim_Compiler_Artifacts"],
  "feature_vector": [1.0, 0.4167, 0.0, 0.0, 1.0, 0.0, 0.0, 0.5333, 0.4, 0.754, 0.0, 1.8, 1.0, 0.0, 0.0, 0.0, 0.0],
  "findings": [
    "[HIGH] Complete NimMain initialization hierarchy confirmed",
    "[DEFINITIVE] nimGC_setStackBottom: GC stack boundary in host process"
  ]
}
```

---

## Platform Support

| Platform | Scan PE files | Build |
|---|---|---|
| macOS (arm64 / x86_64) | ✅ | ✅ |
| Linux (x86_64 / arm) | ✅ | ✅ |
| Windows (x64) | ✅ | ✅ |
