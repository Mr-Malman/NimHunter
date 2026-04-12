# NimHunter: Project Roadmap & Academic Implementation Status

NimHunter v2 implements the core methodologies outlined in the research thesis: *"The Transpilation Signature: A Multi-Layered Detection Framework for Nim-Compiled Malicious Binaries"*. 

To maintain real-world performance while achieving research-grade detection, the framework is implemented in phases. This document delineates what is currently active in the engine (MVP) versus what is planned for future academic iterations.

---

## ✅ Phase 1: Structural Invariant MVP (Current Release)

This phase establishes the baseline "Transpilation Signature" by scanning for invariants that mutation engines cannot strip.

| Feature Area | Status | Paper Reference | Implementation Details |
|---|---|---|---|
| **NimMain Hierarchy** | ✅ Active | pp. 2-3 | Detects the `NimMain` -> `NimMainInner` -> `NimMainModule` cascade via structural byte signatures. |
| **GC Marker Clustering** | ✅ Active | pp. 3-4 | Locates `nimRegisterGlobalMarker` Xrefs to anchor the main logic. |
| **ORC/ARC Analysis** | ✅ Active | pp. 3-4 | Distinguishes GC modes via tri-color motifs and `=copy`/`=destroy` hooks. |
| **Forensic Demangling** | ✅ Active | p. 4 | Extracts developer package paths, escaping schemes, and Nim versions. |
| **_TM String Structs** | ✅ Active | pp. 4-5 | Recovers obfuscated C2 strings by parsing the length+payload structure in `.rdata`. |
| **Offensive Libraries** | ✅ Active | p. 5 | Flags high-risk third-party imports like `winim`, `strenc`, and `ptr_math`. |
| **Poly/Meta Resilience** | ✅ Active | pp. 5-6 | Evaluates how mutation-resistant the current detection was against metamorphic toolkits. |
| **YARA Layer** | ✅ Active | p. 5 | Provides the foundational static artifact detection layer. |
| **ML Heuristic** | ✅ Active | p. 7 | Lightweight linear ensemble weighting for 10-point confidence scoring. |

---

## 🚀 Phase 2: Advanced Disassembly & Semantic Vectors (In Development)

Phase 2 transitions the structural analysis from byte-level heuristic scanning to true Control Flow Graph (CFG) reconstruction, as required for deep metamorphic evasion detection.

| Feature Area | Status | Paper Reference | Planned Implementation |
|---|---|---|---|
| **Capstone Disassembly** | 🔲 Planned | p. 7 | Integrating the `capstone` Nim bindings to accurately reconstruct the `.text` CFG rather than relying on raw `0xE8` (CALL) opcode density. |
| **Site Neural Networks** | 🔲 Planned | p. 5 | Using topological call-graph data to classify the "skeletal control flow" of the Nim runtime regardless of instruction permutation. |
| **ONNX Runtime Ensemble** | 🔲 Planned | p. 7 | Replacing the heuristic ML layer with a trained ensemble classifier (XGBoost/DNN) exported to ONNX format. (Draft scripts available in `scripts/train_model.py`). |

---

## 🔭 Phase 3: BERT-based Toolchain Provenance

The final research phase introduces transformer models to identify transpilation signatures semantically.

| Feature Area | Status | Paper Reference | Planned Implementation |
|---|---|---|---|
| **BERT / asm2vec** | 🔲 Research | p. 6 | Fine-tuning a BERT-based model (similar to ToolPhet) to create instruction-level embeddings. This allows the framework to detect the semantic intent of the Nim GC initialization even if the GCC/Clang backend heavily optimizes the instruction set. |
| **ELF Support** | 🔲 Planned | p. 7 | Expanding the internal `pe_parser.nim` to support Linux ELF binaries for full multi-platform malware analysis. |
