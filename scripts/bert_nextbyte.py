#!/usr/bin/env python3
# scripts/bert_nextbyte.py — Byte-Level Sequence Anomaly Scoring
# NimHunter v2 — Chapter 4.5 / 5.2 implementation
#
# Implements a byte-level bigram Language Model trained on known Nim binary patterns.
# Computes perplexity of new binary under the Nim LM — low perplexity = looks like Nim.
#
# Architecture:
#   - Bigram LM (P[b_t | b_{t-1}]) trained on Nim PE bytes  ← default (fast, no GPU)
#   - BERT hook: when models/byte_bert/ exists, uses HuggingFace BERT instead
#
# Score:
#   - nim_perplexity_score: 0–10 (higher = more Nim-like byte patterns)
#
# Usage:
#   # Train on your malware samples first:
#   .venv/bin/python3.13 scripts/bert_nextbyte.py --train data/samples/malware/
#
#   # Score a new file:
#   .venv/bin/python3.13 scripts/bert_nextbyte.py data/samples/malware/nim_simple_refc.exe

import sys, os, json, glob, pickle
import numpy as np

MODEL_PATH = "models/byte_bigram.pkl"
CHUNK_SIZE  = 8192   # bytes to sample from each binary for training/scoring


# ── Bigram Language Model ─────────────────────────────────────────────────────

class ByteBigramLM:
    """
    Byte-level bigram language model.
    Learns P(b_t | b_{t-1}) from a corpus of PE files.
    Smoothed with add-k smoothing to handle unseen transitions.
    """

    def __init__(self, k_smooth=1.0):
        self.k = k_smooth
        # Transition count matrix: counts[prev][cur]
        self.counts = np.zeros((256, 256), dtype=np.float64)
        self.trained = False
        self.nim_mean_perplexity   = None
        self.benign_mean_perplexity = None

    def train(self, byte_sequences: list):
        """Train on a list of byte arrays."""
        for seq in byte_sequences:
            if len(seq) < 2: continue
            for i in range(len(seq) - 1):
                self.counts[seq[i], seq[i+1]] += 1
        self.trained = True

    def log_prob(self, prev: int, cur: int) -> float:
        """Log P(cur | prev) with add-k smoothing."""
        num = self.counts[prev, cur] + self.k
        den = self.counts[prev].sum() + self.k * 256
        return np.log(num / den)

    def perplexity(self, seq: bytes) -> float:
        """Compute perplexity of a byte sequence under the LM."""
        if not self.trained or len(seq) < 2:
            return 1000.0
        log_sum = sum(self.log_prob(seq[i], seq[i+1]) for i in range(len(seq)-1))
        avg_log = log_sum / (len(seq) - 1)
        return float(np.exp(-avg_log))

    def save(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({
                "counts": self.counts,
                "k": self.k,
                "nim_mean": self.nim_mean_perplexity,
                "benign_mean": self.benign_mean_perplexity,
            }, f)

    def load(self, path: str):
        with open(path, "rb") as f:
            d = pickle.load(f)
        self.counts  = d["counts"]
        self.k       = d["k"]
        self.nim_mean_perplexity    = d.get("nim_mean")
        self.benign_mean_perplexity = d.get("benign_mean")
        self.trained = True


# ── BERT hook (future GPU integration) ────────────────────────────────────────

def try_bert_score(pe_path: str) -> "float | None":
    """
    If models/byte_bert/ exists (fine-tuned BERT on bytes), use it instead.
    Returns confidence score [0, 1] or None if model not available.
    
    To train a real BERT model (requires ≥500 binary samples):
      pip install transformers datasets
      python3 scripts/train_byte_bert.py   # (future script)
    """
    bert_path = "models/byte_bert"
    if not os.path.isdir(bert_path):
        return None
    try:
        from transformers import pipeline
        clf = pipeline("text-classification", model=bert_path, tokenizer=bert_path)
        # Read 512 bytes, encode as space-separated hex tokens
        data = open(pe_path, "rb").read(512)
        text = " ".join(f"{b:02x}" for b in data)
        result = clf(text, truncation=True, max_length=512)[0]
        return result["score"] if result["label"] == "NIM" else 1.0 - result["score"]
    except Exception:
        return None


# ── Train ─────────────────────────────────────────────────────────────────────

def train(malware_dir: str, benign_dir: str = None):
    """Train the bigram LM on Nim malware samples and optionally benign samples."""
    lm = ByteBigramLM(k_smooth=0.5)

    nim_seqs   = []
    benign_seqs = []

    print(f"[*] Training bigram LM on {malware_dir}")
    for path in glob.glob(os.path.join(malware_dir, "*.exe")):
        data = open(path, "rb").read()
        # Use .text section bytes if identifiable, else full binary chunk
        chunk = data[:CHUNK_SIZE]
        nim_seqs.append(chunk)

    if not nim_seqs:
        print(f"[!] No .exe files found in {malware_dir}")
        return

    lm.train(nim_seqs)

    # Calibrate perplexity on Nim samples
    nim_perps = [lm.perplexity(s) for s in nim_seqs]
    lm.nim_mean_perplexity = float(np.mean(nim_perps))
    print(f"    Nim mean perplexity: {lm.nim_mean_perplexity:.1f}  (n={len(nim_seqs)})")

    # Calibrate on benign if available
    if benign_dir and os.path.isdir(benign_dir):
        for path in glob.glob(os.path.join(benign_dir, "*.exe")):
            data = open(path, "rb").read()
            benign_seqs.append(data[:CHUNK_SIZE])
        if benign_seqs:
            benign_perps = [lm.perplexity(s) for s in benign_seqs]
            lm.benign_mean_perplexity = float(np.mean(benign_perps))
            print(f"    Benign mean perplexity: {lm.benign_mean_perplexity:.1f}  (n={len(benign_seqs)})")

    lm.save(MODEL_PATH)
    print(f"[✓] Model saved → {MODEL_PATH}")
    return lm


# ── Score ─────────────────────────────────────────────────────────────────────

def score(pe_path: str) -> dict:
    """
    Score a PE file using the byte bigram LM.
    Returns dict with perplexity, nim_score (0-10), interpretation.
    """
    result = {
        "module":              "bert_nextbyte",
        "perplexity":          None,
        "nim_perplexity_ref":  None,
        "nim_score":           0,
        "interpretation":      "model not trained",
        "bert_available":      False,
        "error":               None,
    }

    # Try BERT first
    bert_conf = try_bert_score(pe_path)
    if bert_conf is not None:
        result["bert_available"] = True
        result["nim_score"]      = int(bert_conf * 10)
        result["interpretation"] = f"BERT confidence: {bert_conf:.3f}"
        return result

    # Fall back to bigram LM
    if not os.path.exists(MODEL_PATH):
        result["error"] = (
            f"Bigram model not trained. Run:\n"
            f"  .venv/bin/python3.13 scripts/bert_nextbyte.py "
            f"--train data/samples/malware/ data/samples/benign/"
        )
        return result

    lm = ByteBigramLM()
    try:
        lm.load(MODEL_PATH)
    except Exception as e:
        result["error"] = str(e)
        return result

    try:
        data = open(pe_path, "rb").read()
        sample = data[:CHUNK_SIZE]
    except Exception as e:
        result["error"] = str(e)
        return result

    perp = lm.perplexity(sample)
    result["perplexity"] = round(perp, 2)
    result["nim_perplexity_ref"] = lm.nim_mean_perplexity

    if lm.nim_mean_perplexity:
        # Ratio: perplexity close to Nim mean → high score
        ratio = perp / lm.nim_mean_perplexity
        # ratio near 1.0 = very Nim-like, ratio > 3.0 = very unlike Nim
        nim_score = max(0, 10 - int(abs(np.log(ratio)) * 5))
        result["nim_score"] = nim_score

        if ratio < 1.5:
            result["interpretation"] = "Byte patterns highly consistent with Nim compiler output"
        elif ratio < 3.0:
            result["interpretation"] = "Byte patterns moderately consistent with Nim"
        else:
            result["interpretation"] = "Byte patterns dissimilar to known Nim binaries"
    else:
        result["interpretation"] = "Benign baseline not calibrated — train with benign samples too"

    return result


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]

    if not args:
        print("Usage:")
        print("  Train:  .venv/bin/python3.13 scripts/bert_nextbyte.py --train <malware_dir> [benign_dir]")
        print("  Score:  .venv/bin/python3.13 scripts/bert_nextbyte.py <pe_file.exe>")
        sys.exit(1)

    if args[0] == "--train":
        malware_dir = args[1] if len(args) > 1 else "data/samples/malware"
        benign_dir  = args[2] if len(args) > 2 else "data/samples/benign"
        train(malware_dir, benign_dir)
    else:
        out = score(args[0])
        print(json.dumps(out, indent=2))
