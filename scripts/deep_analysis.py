#!/usr/bin/env python3
# scripts/deep_analysis.py — NimHunter Deep Analysis Orchestrator
# NimHunter v2 — Master script for all 4 advanced analysis modules
#
# Runs: CFG+GIN, BERT Next-Byte, ACD Anomaly, LIME Explanation
# Returns unified JSON with all scores and findings.
#
# Usage (standalone):
#   .venv/bin/python3.13 scripts/deep_analysis.py <pe_file.exe>
#
# Usage (integrated — called by nimhunter --deep):
#   ./nimhunter --deep data/samples/malware/sample.exe

import sys, os, json, subprocess

PYTHON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".venv", "bin", "python3.13")
if not os.path.exists(PYTHON):
    PYTHON = sys.executable  # fallback to whatever python is running this

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))


def run_module(script_name: str, pe_path: str, extra_args: list = None) -> dict:
    """Run a sub-module script and capture its JSON output."""
    script = os.path.join(SCRIPTS_DIR, script_name)
    cmd = [PYTHON, script] + (extra_args or []) + [pe_path]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if r.stdout.strip():
            return json.loads(r.stdout)
        return {"error": r.stderr.strip()[:200] or "no output"}
    except subprocess.TimeoutExpired:
        return {"error": f"{script_name} timed out after 60s"}
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse error: {e}", "raw": r.stdout[:200]}
    except Exception as e:
        return {"error": str(e)}


def run_lime(pe_path: str, nimhunter_json: dict) -> dict:
    """Run LIME with the feature vector from nimhunter --json output."""
    script = os.path.join(SCRIPTS_DIR, "lime_explain.py")
    fv = nimhunter_json.get("feature_vector", [])
    if not fv:
        return {"module": "lime_explain", "error": "No feature_vector in nimhunter JSON"}

    # Write clean JSON to temp file for LIME script
    import tempfile, re
    # Strip log-prefix lines from the nimhunter JSON before writing
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(nimhunter_json, f)
        tmp = f.name

    try:
        r = subprocess.run([PYTHON, script, tmp], capture_output=True, text=True, timeout=120)
        stdout = r.stdout.strip()
        if not stdout:
            return {"module": "lime_explain", "error": r.stderr.strip()[:300]}
        # Extract JSON block (LIME script may print progress lines)
        m = re.search(r"\{.*\}", stdout, re.DOTALL)
        if m:
            return json.loads(m.group())
        return {"module": "lime_explain", "error": f"No JSON in LIME output: {stdout[:200]}"}
    except Exception as e:
        return {"module": "lime_explain", "error": str(e)}
    finally:
        os.unlink(tmp)



def get_nimhunter_json(pe_path: str) -> dict:
    """Run nimhunter --json to get the base analysis."""
    nimhunter = os.path.join(os.path.dirname(SCRIPTS_DIR), "nimhunter")
    if not os.path.exists(nimhunter):
        return {}
    env = {**os.environ, "PATH": "/opt/homebrew/bin:" + os.environ.get("PATH", "")}
    try:
        r = subprocess.run([nimhunter, "--json", pe_path],
                           capture_output=True, text=True, timeout=30, env=env)
        import re
        m = re.search(r"\{.*\}", r.stdout, re.DOTALL)
        if m:
            return json.loads(m.group())
    except Exception:
        pass
    return {}


def deep_analyze(pe_path: str, nimhunter_json: dict = None) -> dict:
    """
    Run all 4 deep analysis modules and return unified result.
    
    Args:
        pe_path:        path to PE file
        nimhunter_json: optional pre-computed nimhunter --json output
                        (avoids running nimhunter twice)
    """
    print(f"[*] Deep analysis: {os.path.basename(pe_path)}", file=sys.stderr)

    # Get base nimhunter analysis if not provided
    if not nimhunter_json:
        print("[*]   Running base scan...", file=sys.stderr)
        nimhunter_json = get_nimhunter_json(pe_path)

    results = {
        "file":   pe_path,
        "module": "deep_analysis",
        "layers": {},
        "deep_score":      0,
        "deep_max":        30,
        "combined_total":  nimhunter_json.get("total_score", 0),
        "findings":        [],
    }

    # ── Module 1: CFG + GIN ──────────────────────────────────────────────────
    print("[*]   CFG + GIN...", file=sys.stderr)
    gin = run_module("cfg_gin.py", pe_path)
    results["layers"]["cfg_gin"] = gin
    gin_score = int(gin.get("gin_score", 0))
    results["deep_score"] += gin_score

    motifs = gin.get("motifs", {})
    if motifs.get("nimMain_cascade"):
        results["findings"].append("[GIN] NimMain cascade CFG pattern confirmed")
    if motifs.get("orc_back_edge"):
        results["findings"].append("[GIN] ORC GC back-edge loop detected in CFG")
    if motifs.get("gc_marker_fan_out"):
        results["findings"].append("[GIN] GC marker fan-out topology detected")

    # ── Module 2: BERT Next-Byte ─────────────────────────────────────────────
    print("[*]   Byte-level LM...", file=sys.stderr)
    bert = run_module("bert_nextbyte.py", pe_path)
    results["layers"]["bert_nextbyte"] = bert
    bert_score = int(bert.get("nim_score", 0))
    results["deep_score"] += bert_score

    if bert_score >= 7:
        results["findings"].append(f"[BERT] Byte patterns highly consistent with Nim compiler (score {bert_score}/10)")

    # ── Module 3: ACD Anomaly ────────────────────────────────────────────────
    print("[*]   ACD anomaly...", file=sys.stderr)
    # ACD needs feature vector from nimhunter JSON
    if nimhunter_json.get("feature_vector"):
        acd_script = os.path.join(SCRIPTS_DIR, "acd_anomaly.py")
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(nimhunter_json, f)
            tmp = f.name
        try:
            r = subprocess.run([PYTHON, acd_script, "--score", tmp],
                               capture_output=True, text=True, timeout=30)
            if r.stdout.strip():
                acd = json.loads(r.stdout)
            else:
                acd = {"module": "acd_anomaly", "error": r.stderr[:200]}
        except Exception as e:
            acd = {"module": "acd_anomaly", "error": str(e)}
        finally:
            os.unlink(tmp)
    else:
        acd = {"module": "acd_anomaly", "error": "No feature_vector from base scan"}

    results["layers"]["acd_anomaly"] = acd
    acd_score = int(acd.get("anomaly_score", 0))
    results["deep_score"] += acd_score

    if acd_score >= 3:
        results["findings"].append(
            f"[ACD] Feature vector highly anomalous vs. benign distribution "
            f"(ACD={acd.get('acd_total','?')}, score {acd_score}/5)"
        )

    # ── Module 4: LIME Explanation ───────────────────────────────────────────
    print("[*]   LIME explanation...", file=sys.stderr)
    lime = run_lime(pe_path, nimhunter_json)
    results["layers"]["lime"] = lime

    if lime.get("top_features"):
        results["findings"].append(
            "[LIME] Top contributors: " + " | ".join(lime["top_features"][:3])
        )

    # ── Combined total ────────────────────────────────────────────────────────
    base = nimhunter_json.get("total_score", 0)
    deep = min(results["deep_score"], 30)
    # Normalize combined score to 100: base(max90) + deep(max30) → normalize
    combined_raw = base + deep
    results["deep_score"]     = deep
    results["combined_total"] = min(100, int(combined_raw * 100 / 120))

    print(f"[✓]   Deep score: {deep}/30  |  Combined: {results['combined_total']}/100", file=sys.stderr)
    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: .venv/bin/python3.13 scripts/deep_analysis.py <pe_file.exe>")
        sys.exit(1)

    pe_path = sys.argv[1]
    if not os.path.exists(pe_path):
        print(f"[!] File not found: {pe_path}")
        sys.exit(1)

    result = deep_analyze(pe_path)
    print(json.dumps(result, indent=2))
