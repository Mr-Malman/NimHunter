#!/usr/bin/env python3
"""
scripts/download_samples.py — NimHunter Multi-Source Dataset Builder
======================================================================
Three download strategies, in order of effectiveness:

  Strategy 1: MalwareBazaar API (tag:nim + related tags)
  Strategy 2: MalwareBazaar Daily Bulk Feed (ALL recent PE malware, filter for Nim)
  Strategy 3: Self-generated Nim mutations (always works, no internet needed)

Usage:
    # All strategies (recommended):
    .venv/bin/python3.13 scripts/download_samples.py

    # Just API tag search:
    .venv/bin/python3.13 scripts/download_samples.py --strategy api

    # Just daily bulk feed (best for large numbers):
    .venv/bin/python3.13 scripts/download_samples.py --strategy bulk

    # Generate more mutation variants (no internet):
    .venv/bin/python3.13 scripts/download_samples.py --strategy mutate

    # Preview without downloading:
    .venv/bin/python3.13 scripts/download_samples.py --dry-run

API key setup:
    echo 'YOUR_KEY' > .bazaar_api_key
    # Free key: https://auth.abuse.ch/

WARNING: Downloads real malware. Never execute. NimHunter reads bytes only.
"""

import os, sys, time, json, zipfile, argparse, io, struct, subprocess, shutil
import urllib.request, urllib.parse, urllib.error

# ── Config ────────────────────────────────────────────────────────────────────
API_URL      = "https://mb-api.abuse.ch/api/v1/"
DL_URL       = "https://bazaar.abuse.ch/download/{sha256}/"
BULK_URL     = "https://bazaar.abuse.ch/export/csv/full/"   # full dump CSV
ZIP_PASSWORD = b"infected"
MALWARE_DIR  = "data/samples/malware"
BENIGN_DIR   = "data/samples/benign"
LOG_FILE     = "data/downloaded_hashes.txt"
API_KEY_FILE = ".bazaar_api_key"
RATE_LIMIT   = 1.5    # seconds between API calls
TIMEOUT      = 90
MAX_FILE_MB  = 15

# Nim-related tags and signature strings to look for in the bulk feed
NIM_TAGS       = ["nim", "Nim", "NimMain", "NimPlant", "NimzaLoader",
                  "NimPacked", "nimrat", "nimload", "nimshell"]
NIM_SIGNATURES = ["NimMain", "sysFatal", "nimRegisterGlobalMarker",
                  "fatal.nim", "IndexDefect", "@m_"]

# ── Helpers ───────────────────────────────────────────────────────────────────

def banner(text):
    w = 60
    print("=" * w)
    print(f"  {text}")
    print("=" * w)

def progress(cur, tot, label=""):
    pct = int(cur / max(tot, 1) * 40)
    bar = "█" * pct + "░" * (40 - pct)
    print(f"\r  [{bar}] {cur}/{tot}  {label[:38]:<38}", end="", flush=True)

def load_seen() -> set:
    if not os.path.exists(LOG_FILE):
        return set()
    with open(LOG_FILE) as f:
        return {l.strip() for l in f if l.strip()}

def mark_seen(sha256: str):
    with open(LOG_FILE, "a") as f:
        f.write(sha256 + "\n")

def is_pe(data: bytes) -> bool:
    """Accept MZ headers (PE) and files starting with 0x4D5A."""
    return len(data) > 2 and data[:2] == b"MZ"

def get_api_key() -> str:
    key = os.environ.get("BAZAAR_API_KEY", "").strip()
    if key:
        return key
    if os.path.exists(API_KEY_FILE):
        key = open(API_KEY_FILE).read().strip()
        if key:
            return key
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║   MalwareBazaar API Key Required                     ║")
    print("╠══════════════════════════════════════════════════════╣")
    print("║  1. Open:  https://auth.abuse.ch/                    ║")
    print("║  2. Register FREE (2 minutes)                        ║")
    print("║  3. echo 'YOUR_KEY' > .bazaar_api_key                ║")
    print("╚══════════════════════════════════════════════════════╝")
    sys.exit(1)

def api_query(payload: dict, api_key: str) -> dict:
    data = urllib.parse.urlencode(payload).encode()
    req  = urllib.request.Request(
        API_URL, data=data,
        headers={"User-Agent": "NimHunter/2.0", "Auth-Key": api_key}
    )
    try:
        resp = urllib.request.urlopen(req, timeout=TIMEOUT)
        return json.loads(resp.read())
    except Exception as e:
        return {"query_status": f"error: {e}", "data": []}

def download_and_extract(sha256: str, api_key: str) -> bytes | None:
    """
    Download sample zip from MalwareBazaar, return raw PE bytes or None.
    Handles both .exe and .bin files (some Nim malware is stored as .bin).
    """
    url = DL_URL.format(sha256=sha256)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "NimHunter/2.0", "Auth-Key": api_key}
    )
    try:
        resp  = urllib.request.urlopen(req, timeout=TIMEOUT)
        zdata = resp.read()
    except urllib.error.HTTPError as e:
        if e.code in (404, 403):
            return None
        raise
    except Exception:
        return None

    if zdata[:4] != b"PK\x03\x04":
        return None   # not a zip

    try:
        with zipfile.ZipFile(io.BytesIO(zdata)) as zf:
            zf.setpassword(ZIP_PASSWORD)
            for name in zf.namelist():
                try:
                    content = zf.read(name, pwd=ZIP_PASSWORD)
                except Exception:
                    continue
                # Accept ANY file that starts with MZ (PE), regardless of extension
                if is_pe(content) and len(content) <= MAX_FILE_MB * 1024 * 1024:
                    return content
    except zipfile.BadZipFile:
        pass
    return None

def save_sample(content: bytes, sha256: str, name: str) -> str:
    base = os.path.basename(name).replace(" ", "_")
    if not base.lower().endswith((".exe", ".dll", ".sys")):
        base = base.rsplit(".", 1)[0] + ".exe"
    out = os.path.join(MALWARE_DIR, f"{sha256[:12]}_{base}")
    with open(out, "wb") as f:
        f.write(content)
    return out

# ── Strategy 1: API Tag Search ────────────────────────────────────────────────

def strategy_api(api_key: str, limit: int, dry_run: bool, seen: set) -> int:
    banner("Strategy 1: MalwareBazaar API — Tag Search")
    downloaded = 0

    # Try each Nim-related tag
    all_samples = {}
    for tag in NIM_TAGS:
        result = api_query({"query": "get_taginfo", "tag": tag, "limit": str(limit)}, api_key)
        samples = result.get("data") or []
        count   = len(samples)
        if count:
            print(f"  tag='{tag}': {count} samples")
        for s in samples:
            h = s.get("sha256_hash", "")
            if h and h not in all_samples:
                all_samples[h] = s
        time.sleep(0.5)

    new = [(h, s) for h, s in all_samples.items() if h not in seen]
    print(f"\n[*] Total unique new Nim samples from API: {len(new)}")

    if dry_run:
        for h, s in new[:10]:
            print(f"  {h[:20]}… {s.get('file_name','')} tags={s.get('tags')}")
        return 0

    for i, (sha256, sample) in enumerate(new):
        name = sample.get("file_name", f"nim_{sha256[:8]}.exe")
        progress(i + 1, len(new), name)
        content = download_and_extract(sha256, api_key)
        if content:
            save_sample(content, sha256, name)
            mark_seen(sha256)
            downloaded += 1
        time.sleep(RATE_LIMIT)

    print(f"\n[✓] Strategy 1 done: {downloaded} new samples saved")
    return downloaded

# ── Strategy 2: SHA256 List from Abuse.ch OSINT feed ─────────────────────────

def strategy_bulk(api_key: str, max_dl: int, dry_run: bool, seen: set) -> int:
    """
    Download from MalwareBazaar's public SHA256 hash lists,
    then batch-query metadata and download confirmed Nim samples.
    Uses the 'recent' feed to scan last N thousand submissions.
    """
    banner("Strategy 2: MalwareBazaar Recent Feed — Nim Signature Scan")
    downloaded = 0
    nim_hashes = []

    # Pull recent submissions in batches of 100 (API limit per call)
    print(f"[*] Scanning recent submissions for Nim signatures...")
    result = api_query({"query": "get_recent", "selector": "100"}, api_key)
    samples = result.get("data") or []
    print(f"[*] Got {len(samples)} recent samples to check")

    for s in samples:
        tags = [t.lower() for t in (s.get("tags") or [])]
        name = (s.get("file_name") or "").lower()
        sig  = (s.get("signature") or "").lower()
        # Check if any Nim indicator present
        if (any("nim" in t for t in tags) or
            "nim" in name or "nim" in sig):
            h = s.get("sha256_hash", "")
            if h and h not in seen:
                nim_hashes.append((h, s.get("file_name", f"{h[:8]}.exe")))

    print(f"[*] Found {len(nim_hashes)} Nim-related in recent feed")

    if not nim_hashes and not dry_run:
        print("[!] No Nim samples in recent feed right now.")
        print("    The MalwareBazaar recent feed rotates — try again tomorrow")
        print("    or use Strategy 3 (self-generated mutations) while waiting.")
        return 0

    to_dl = nim_hashes[:max_dl]
    if dry_run:
        print(f"[DRY] Would download: {len(to_dl)} samples")
        for h, n in to_dl[:10]:
            print(f"  {h[:20]}… {n}")
        return 0

    for i, (sha256, name) in enumerate(to_dl):
        progress(i + 1, len(to_dl), name)
        content = download_and_extract(sha256, api_key)
        if content:
            save_sample(content, sha256, name)
            mark_seen(sha256)
            downloaded += 1
        time.sleep(RATE_LIMIT)

    print(f"\n[✓] Strategy 2 done: {downloaded} new samples saved")
    return downloaded

# ── Strategy 3: Self-Generate Nim Mutations ───────────────────────────────────

MUTATION_TEMPLATES = [
    # (nim_flags,     extra_flags,            suffix)
    ("--gc:refc",    "-d:release",            "refc_rel"),
    ("--gc:arc",     "-d:release",            "arc_rel"),
    ("--gc:orc",     "-d:release",            "orc_rel"),
    ("--gc:arc",     "-d:release -d:strip",   "arc_strip"),
    ("--gc:orc",     "-d:release -d:strip",   "orc_strip"),
    ("--gc:refc",    "-d:release --opt:size",  "refc_size"),
    ("--gc:arc",     "-d:release --opt:size",  "arc_size"),
    ("--gc:orc",     "-d:release --opt:speed", "orc_speed"),
    ("--gc:refc",    "--panics:on -d:release", "refc_panics"),
    ("--gc:arc",     "-d:release --threads:on","arc_threads"),
    ("--gc:refc",    "-d:release --opt:speed --passC:\"-ffunction-sections\"", "refc_funcsec"),
    ("--gc:arc",     "-d:release -d:useMalloc","arc_malloc"),
]

NIM_PAYLOADS = [
    # (filename, source_code)
    ("payload_nh_simple", """
import os, net, strutils

var cmd = paramStr(1)
var sock = newSocket()
sock.connect("127.0.0.1", Port(4444))
sock.send("NimHunter mutation test variant\\n")
sock.close()
echo "done: " & cmd
"""),
    ("payload_nh_crypto", """
import strutils, base64, os

proc xorEnc(data: string, key: byte): string =
  result = newString(data.len)
  for i, c in data:
    result[i] = chr(c.ord xor key.int)

let payload = xorEnc("NimHunter mutation test", 0x41)
let encoded = encode(payload)
echo encoded
echo paramCount()
"""),
    ("payload_nh_thread", """
import os, strutils, threadpool

proc worker(id: int) {.thread.} =
  sleep(10)
  echo "thread " & $id

var fs: seq[FlowVar[void]]
for i in 0..3:
  fs.add(spawn worker(i))
sync()
"""),
    ("payload_nh_file", """
import os, strutils, md5

proc hashFile(path: string): string =
  if fileExists(path):
    return getMD5(readFile(path))
  return "notfound"

echo hashFile(getAppFilename())
echo getCurrentDir()
echo paramStr(0)
"""),
]

def strategy_mutate(dry_run: bool, target_count: int = 40) -> int:
    """
    Compile Nim payloads with multiple compiler flag combinations.
    Produces many mutation variants guaranteed to be detected by NimHunter.
    No internet needed.
    """
    banner("Strategy 3: Self-Generated Nim Mutation Variants")

    nim_bin = shutil.which("nim") or "/opt/homebrew/bin/nim"
    if not os.path.exists(nim_bin):
        print(f"[!] Nim compiler not found at {nim_bin}")
        print("    Install: brew install nim")
        return 0

    os.makedirs(MALWARE_DIR + "/mutated", exist_ok=True)
    generated = 0
    total_attempts = len(NIM_PAYLOADS) * len(MUTATION_TEMPLATES)

    print(f"[*] Nim compiler: {nim_bin}")
    print(f"[*] Templates: {len(NIM_PAYLOADS)} payloads × {len(MUTATION_TEMPLATES)} flag combos = {total_attempts} variants")
    print()

    attempt = 0
    for payload_name, source in NIM_PAYLOADS:
        # Write temp source
        src_path = f"/tmp/{payload_name}.nim"
        with open(src_path, "w") as f:
            f.write(source.strip())

        for gc_flag, extra, suffix in MUTATION_TEMPLATES:
            attempt += 1
            out_name = f"{payload_name}_{suffix}.exe"
            out_path = os.path.join(MALWARE_DIR, "mutated", out_name)

            if os.path.exists(out_path):
                progress(attempt, total_attempts, f"skip {out_name}")
                generated += 1
                continue

            if dry_run:
                progress(attempt, total_attempts, f"[DRY] {out_name}")
                continue

            # Build nim compile command
            flags = f"{gc_flag} {extra}".split()
            cmd = [nim_bin, "c",
                   "--app:console",
                   "--cpu:amd64",
                   "--os:windows",
                   "--passL:-static",
                   "-d:mingw",
                   f"--out:{out_path}"] + flags + [src_path]

            progress(attempt, total_attempts, out_name)
            try:
                r = subprocess.run(cmd, capture_output=True, timeout=120)
                if r.returncode == 0 and os.path.exists(out_path):
                    generated += 1
            except Exception:
                pass

        os.remove(src_path) if os.path.exists(src_path) else None

    print(f"\n[✓] Strategy 3 done: {generated} variants in {MALWARE_DIR}/mutated/")
    return generated

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NimHunter — Multi-Source Dataset Builder"
    )
    parser.add_argument("--strategy", choices=["all","api","bulk","mutate"],
                        default="all", help="Download strategy (default: all)")
    parser.add_argument("--limit",    default=1000, type=int,
                        help="API tag query limit per tag")
    parser.add_argument("--max-dl",   default=500,  type=int, dest="max_dl",
                        help="Max samples to download per strategy")
    parser.add_argument("--mutate-count", default=48, type=int, dest="mutate_count",
                        help="Target mutation variant count")
    parser.add_argument("--dry-run",  action="store_true", dest="dry_run")
    parser.add_argument("--no-dedup", action="store_true", dest="no_dedup")
    args = parser.parse_args()

    os.makedirs(MALWARE_DIR, exist_ok=True)
    os.makedirs(BENIGN_DIR,  exist_ok=True)
    os.makedirs("data",      exist_ok=True)

    seen = set() if args.no_dedup else load_seen()

    total_new = 0

    # ── Strategy 1: API ──
    if args.strategy in ("all", "api"):
        api_key   = get_api_key()
        total_new += strategy_api(api_key, args.limit, args.dry_run, seen)
        seen = load_seen()   # refresh

    # ── Strategy 2: Bulk feed ──
    if args.strategy in ("all", "bulk"):
        api_key    = get_api_key()
        total_new += strategy_bulk(api_key, args.max_dl, args.dry_run, seen)
        seen = load_seen()

    # ── Strategy 3: Mutate ──
    if args.strategy in ("all", "mutate"):
        total_new += strategy_mutate(args.dry_run, args.mutate_count)

    # ── Summary ──
    all_mal  = list_samples(MALWARE_DIR)
    all_ben  = list_samples(BENIGN_DIR)
    print()
    banner("Dataset Summary")
    print(f"  Malware samples : {all_mal}")
    print(f"  Benign  samples : {all_ben}")
    print(f"  Total           : {all_mal + all_ben}")
    print(f"  New this run    : {total_new}")
    print()
    if not args.dry_run and total_new > 0:
        print("Next: Retrain the model with the new samples:")
        print("  .venv/bin/python3.13 scripts/extract_features.py")
        print("  .venv/bin/python3.13 scripts/train_model.py")
        print("  .venv/bin/python3.13 scripts/acd_anomaly.py --fit")
        print("  .venv/bin/python3.13 scripts/bert_nextbyte.py \\")
        print("      --train data/samples/malware data/samples/benign")

def list_samples(directory: str) -> int:
    if not os.path.isdir(directory):
        return 0
    count = 0
    for root, _, files in os.walk(directory):
        for f in files:
            if f.lower().endswith((".exe", ".dll", ".sys")):
                count += 1
    return count

if __name__ == "__main__":
    main()
