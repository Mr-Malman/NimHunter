#!/usr/bin/env python3
"""
scripts/fetch_web_samples.py — NimHunter Web Malware Fetcher
=============================================================
Downloads real-world Nim malware from public threat intel sources:

  Source 1: VX-Underground Nim samples (direct link list)
  Source 2: theZoo GitHub repository (known Nim-coded malware)
  Source 3: VirusShare hash lists (manual paste of SHA256s)
  Source 4: GitHub search — public Nim RATs/loaders (source repos)
  Source 5: Any-Run public sandbox exports

Usage:
    .venv/bin/python3.13 scripts/fetch_web_samples.py --source all
    .venv/bin/python3.13 scripts/fetch_web_samples.py --source vxug
    .venv/bin/python3.13 scripts/fetch_web_samples.py --source thezoo
    .venv/bin/python3.13 scripts/fetch_web_samples.py --source github
    .venv/bin/python3.13 scripts/fetch_web_samples.py --hashes hashes.txt

    # Add SHA256 hashes manually (from VirusShare / VT / etc.):
    .venv/bin/python3.13 scripts/fetch_web_samples.py --hashes my_hashes.txt

WARNING: Downloads real malware. Never execute. Use in a VM or air-gapped machine.
"""

import os, sys, json, time, zipfile, io, subprocess, argparse, shutil
import urllib.request, urllib.error, urllib.parse

MALWARE_DIR  = "data/samples/malware"
LOG_FILE     = "data/downloaded_hashes.txt"
TIMEOUT      = 60
ZIP_PASS     = b"infected"

# ── Known public Nim malware sources ──────────────────────────────────────────

# theZoo: GitHub repo with known malware samples
THEZOO_REPO  = "https://github.com/ytisf/theZoo"
THEZOO_API   = "https://api.github.com/repos/ytisf/theZoo/contents/malwares/Binaries"

# Known Nim malware GitHub repos (source code — can compile for training)
NIM_MALWARE_REPOS = [
    # Name,                    Repo URL,                                    Category
    ("NimPlant",     "https://github.com/chvancooten/NimPlant",          "c2_agent"),
    ("NimlineWhispers", "https://github.com/ajpc500/NimlineWhispers",   "syscall"),
    ("BokuLoader",   "https://github.com/boku7/BokuLoader",              "loader"),
    ("NimShellCodeLoader","https://github.com/milkdevil/NimShellcodeLoader","loader"),
    ("Nimcrypt2",    "https://github.com/icyguider/Nimcrypt2",           "crypter"),
    ("NimDrop",      "https://github.com/f1rstfr4day/NimDrop",           "dropper"),
    ("NimLoader",    "https://github.com/byt3bl33d3r/OffensiveNim",     "offensive"),
    ("NimRed",       "https://github.com/trickster0/OffensiveNim",       "offensive"),
    ("SharpNim",     "https://github.com/krutons/nim-mal",               "general"),
    ("NimHasheroc",  "https://github.com/waldo-irc/LetsLearnNim",        "general"),
]

# VX-Underground direct sample links (public Nim samples shared by VXUG)
VXUG_NIM_URLS = [
    # These are publicly shared research samples from vx-underground.org
    # Add direct download URLs here as they become available
    # Format: (url, filename)
    # Example (these need to be verified):
    # ("https://samples.vx-underground.org/samples/Families/Nim/NimBot.zip", "NimBot.zip"),
]

# Known Nim malware SHA256 hashes from public threat intel (no download needed, just for ref)
KNOWN_NIM_HASHES = """
# Nim malware SHA256 hashes — paste yours here or in a separate file
# Source: MalwareBazaar, VirusShare, VT, Any.Run public reports
# Format: one SHA256 per line (64 hex chars), lines starting with # are ignored

# NimzaLoader samples (BazarLoader built in Nim)
# a3af3d7e825daeffc05e34a784d686bb9f346d48a92c060e1e901c644398d5d7
# 397e4dc12d48fb0c4d80980643581c9416a4bed022d4676f30218fb1f1e1811c
# 07e0b509288c501c57cc8f11b88ac8c06e379b01b74cd910d93cfdff1f9dd7ec

# Add more hashes from VirusShare / VT here:
""".strip()

# ── Helpers ───────────────────────────────────────────────────────────────────

def is_pe(data: bytes) -> bool:
    return len(data) >= 2 and data[:2] == b"MZ"

def load_seen() -> set:
    if not os.path.exists(LOG_FILE): return set()
    return {l.strip() for l in open(LOG_FILE) if l.strip() and not l.startswith("#")}

def mark_seen(h: str):
    with open(LOG_FILE, "a") as f: f.write(h + "\n")

def http_get(url: str, headers: dict = {}) -> bytes | None:
    req = urllib.request.Request(url, headers={
        "User-Agent": "NimHunter/2.0 (research)",
        **headers
    })
    try:
        resp = urllib.request.urlopen(req, timeout=TIMEOUT)
        return resp.read()
    except Exception as e:
        print(f"  [!] GET {url[:60]} → {e}")
        return None

def save_pe(data: bytes, name: str, subdir: str = "") -> str | None:
    if not is_pe(data): return None
    outdir = os.path.join(MALWARE_DIR, subdir) if subdir else MALWARE_DIR
    os.makedirs(outdir, exist_ok=True)
    out = os.path.join(outdir, name.replace(" ", "_"))
    with open(out, "wb") as f: f.write(data)
    return out

def unzip_pe(data: bytes, outdir: str, prefix: str = "") -> list:
    """Extract PE files from a zip archive. Returns list of saved paths."""
    saved = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for pwd in [ZIP_PASS, b"", b"virus", b"infected", b"password"]:
                try:
                    for name in zf.namelist():
                        content = zf.read(name, pwd=pwd)
                        if is_pe(content):
                            base = os.path.basename(name).replace(" ", "_") or f"{prefix}.exe"
                            path = save_pe(content, (prefix + "_" + base)[:80], "")
                            if path: saved.append(path)
                    if saved: break
                except Exception:
                    continue
    except zipfile.BadZipFile:
        pass
    return saved

# ── Source 1: theZoo (GitHub) ─────────────────────────────────────────────────

def fetch_thezoo(subdir: str = "nim") -> int:
    """
    Clone theZoo and extract known Nim malware binary hashes.
    theZoo stores malware as encrypted zips on GitHub.
    """
    print("\n[theZoo] Scanning GitHub repo for Nim-related malware...")

    # Get directory listing via GitHub API
    data = http_get(THEZOO_API)
    if not data:
        print("  [!] Cannot reach theZoo API. Check internet connection.")
        return 0

    items = json.loads(data)
    nim_items = [x for x in items
                 if any(kw in x.get("name","").lower()
                        for kw in ["nim", "nimzaloader", "bazarloader", "cobalt"])]

    print(f"  Found {len(items)} total, {len(nim_items)} Nim-related entries")

    downloaded = 0
    for item in nim_items[:20]:
        name = item.get("name", "")
        url  = item.get("download_url") or item.get("url", "")
        print(f"  Fetching: {name}")
        raw = http_get(url)
        if not raw: continue
        # theZoo stores as encrypted zips
        saved = unzip_pe(raw, MALWARE_DIR, name[:20])
        if not saved:
            # Try saving raw if it's a PE
            if is_pe(raw):
                save_pe(raw, name + ".exe", "thezoo")
                downloaded += 1
        else:
            downloaded += len(saved)
        time.sleep(1)

    print(f"  [✓] theZoo: {downloaded} samples saved")
    return downloaded

# ── Source 2: GitHub Nim Malware Repos (compile from source) ─────────────────

def fetch_github_repos(limit: int = 5) -> int:
    """
    Clone known Nim offensive tool repositories and compile them.
    These are public proof-of-concept tools, useful for training.
    """
    if not shutil.which("git"):
        print("[!] git not installed — skipping GitHub repos")
        return 0
    if not shutil.which("nim") and not os.path.exists("/opt/homebrew/bin/nim"):
        print("[!] nim not installed — skipping GitHub repos")
        return 0

    nim_bin  = shutil.which("nim") or "/opt/homebrew/bin/nim"
    mingw    = "/opt/homebrew/bin/x86_64-w64-mingw32-gcc"
    mingw_ok = os.path.exists(mingw)
    clone_dir = "/tmp/nim_repos"
    os.makedirs(clone_dir, exist_ok=True)

    compiled = 0
    print(f"\n[GitHub] Cloning and compiling {min(limit, len(NIM_MALWARE_REPOS))} Nim repos...")

    for repo_name, repo_url, category in NIM_MALWARE_REPOS[:limit]:
        dest = os.path.join(clone_dir, repo_name)
        outdir = os.path.join(MALWARE_DIR, "github", category)
        os.makedirs(outdir, exist_ok=True)

        print(f"\n  [{repo_name}] Cloning {repo_url}...")

        # Clone
        if os.path.exists(dest):
            subprocess.run(["git", "-C", dest, "pull", "--quiet"],
                           capture_output=True, timeout=60)
        else:
            r = subprocess.run(
                ["git", "clone", "--depth=1", "--quiet", repo_url, dest],
                capture_output=True, timeout=120)
            if r.returncode != 0:
                print(f"    [!] Clone failed")
                continue

        # Find .nim source files
        nim_files = []
        for root, _, files in os.walk(dest):
            for f in files:
                if f.endswith(".nim") and not f.startswith("test"):
                    nim_files.append(os.path.join(root, f))

        print(f"    Found {len(nim_files)} .nim files")

        # Compile each (up to 5 per repo)
        for src in nim_files[:5]:
            out_name = f"{repo_name}_{os.path.basename(src).replace('.nim','.exe')}"
            out_path = os.path.join(outdir, out_name)
            if os.path.exists(out_path): compiled += 1; continue

            # Build compile command
            if mingw_ok:
                cmd = [nim_bin, "c", "--app:console", "--cpu:amd64", "--os:windows",
                       f"--gcc.exe:{mingw}", f"--gcc.linkerexe:{mingw}",
                       "--hints:off", "--warnings:off", "--gc:arc", "-d:release",
                       f"--out:{out_path}", src]
            else:
                out_path = out_path.replace(".exe", "")
                cmd = [nim_bin, "c", "--app:console", "--hints:off", "--warnings:off",
                       "--gc:arc", "-d:release", f"--out:{out_path}", src]

            r = subprocess.run(cmd, capture_output=True, timeout=180)
            if r.returncode == 0 and os.path.exists(out_path):
                print(f"    [✓] Compiled: {out_name}")
                compiled += 1

        time.sleep(1)

    print(f"\n  [✓] GitHub repos: {compiled} samples compiled")
    return compiled

# ── Source 3: Hash list downloader (VirusShare / VT / Any.Run) ───────────────

def fetch_from_hashlist(hashfile: str, bazaar_key: str = "") -> int:
    """
    Download samples by SHA256 hash list.
    Tries MalwareBazaar first (needs API key), then falls back to other sources.

    hashfile format: one SHA256 per line, lines starting with # ignored.
    """
    if not os.path.exists(hashfile):
        print(f"[!] Hash file not found: {hashfile}")
        return 0

    hashes = []
    with open(hashfile) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and len(line) == 64:
                hashes.append(line)

    print(f"\n[HashList] {len(hashes)} SHA256 hashes from {hashfile}")
    seen    = load_seen()
    new     = [h for h in hashes if h not in seen]
    print(f"  {len(new)} new (not yet downloaded)")

    downloaded = 0

    for i, sha256 in enumerate(new):
        print(f"\r  [{i+1}/{len(new)}] {sha256[:24]}…", end="", flush=True)

        # Try MalwareBazaar download
        if bazaar_key:
            from download_samples import download_and_extract
            content = download_and_extract(sha256, bazaar_key)
            if content:
                save_pe(content, sha256[:16] + ".exe")
                mark_seen(sha256)
                downloaded += 1
                time.sleep(1.2)
                continue

        # Try Malshare
        malshare_key = os.environ.get("MALSHARE_KEY", "")
        if malshare_key:
            url = f"https://malshare.com/api.php?apikey={malshare_key}&action=getfile&hash={sha256}"
            data = http_get(url)
            if data and is_pe(data):
                save_pe(data, sha256[:16] + "_malshare.exe")
                mark_seen(sha256)
                downloaded += 1
                time.sleep(1)
                continue

        time.sleep(0.5)

    print(f"\n  [✓] Downloaded {downloaded}/{len(new)} from hash list")
    return downloaded

# ── Source 4: VX-Underground direct URLs ─────────────────────────────────────

def fetch_vxug() -> int:
    """
    Download from VX-Underground public sample links.
    Check https://vx-underground.org/samples.html for current Nim links.
    """
    if not VXUG_NIM_URLS:
        print("\n[VX-Underground] No URLs configured.")
        print("  → Visit: https://vx-underground.org/samples.html")
        print("  → Search for 'Nim' in the family list")
        print("  → Add direct download URLs to VXUG_NIM_URLS in this script")
        return 0

    downloaded = 0
    os.makedirs(os.path.join(MALWARE_DIR, "vxug"), exist_ok=True)
    for url, name in VXUG_NIM_URLS:
        print(f"  Fetching: {name} from VX-UG...")
        data = http_get(url)
        if not data: continue
        if name.endswith(".zip"):
            saved = unzip_pe(data, os.path.join(MALWARE_DIR, "vxug"), name[:20])
            downloaded += len(saved)
        elif is_pe(data):
            save_pe(data, name, "vxug")
            downloaded += 1
        time.sleep(2)

    print(f"  [✓] VX-Underground: {downloaded} samples")
    return downloaded

# ── Summary and Instructions ──────────────────────────────────────────────────

def print_manual_guide():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║      MANUAL DOWNLOAD GUIDE — Real World Nim Malware Sources      ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  1. VirusShare (virusshare.com)                                  ║
║     → Register FREE at https://virusshare.com/register           ║
║     → Hash Lists → Download any recent hash list                 ║
║     → Download samples: https://virusshare.com/torrent           ║
║     → Save SHA256s to: data/nim_hashes.txt                       ║
║     → Run: python3 scripts/fetch_web_samples.py \\               ║
║              --hashes data/nim_hashes.txt                        ║
║                                                                  ║
║  2. theZoo (github.com/ytisf/theZoo)                             ║
║     → Run: python3 scripts/fetch_web_samples.py --source thezoo  ║
║                                                                  ║
║  3. VX-Underground (vx-underground.org)                          ║
║     → Visit: https://vx-underground.org/samples.html             ║
║     → Filter family = "Nim" or search "NimzaLoader"             ║
║     → Download .7z files (password: infected)                    ║
║     → Unzip: 7z x sample.7z -pinfected                          ║
║     → Copy .exe to: data/samples/malware/vxug/                   ║
║                                                                  ║
║  4. GitHub Offensive Nim Repos (compiled from source)            ║
║     → Run: python3 scripts/fetch_web_samples.py --source github   ║
║     → Compiles NimPlant, OffensiveNim, Nimcrypt2, etc.           ║
║                                                                  ║
║  5. Any.Run public sandbox (app.any.run)                         ║
║     → Search: "Nim" in Public Tasks                              ║
║     → Download sample → Copy to data/samples/malware/anyrun/     ║
║                                                                  ║
║  6. MalwareBazaar (already configured)                           ║
║     → Run: python3 scripts/download_samples.py                   ║
║                                                                  ║
║  After adding samples → retrain:                                 ║
║    python3 scripts/extract_features.py                           ║
║    python3 scripts/train_model.py                                ║
╚══════════════════════════════════════════════════════════════════╝
""")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NimHunter — Fetch real-world Nim malware from web sources"
    )
    parser.add_argument("--source", choices=["all","vxug","thezoo","github"],
                        default="all")
    parser.add_argument("--hashes", type=str, default="",
                        help="Path to SHA256 hash list file (VirusShare / VT format)")
    parser.add_argument("--limit", type=int, default=10,
                        help="Max repos to clone for github strategy")
    args = parser.parse_args()

    os.makedirs(MALWARE_DIR, exist_ok=True)
    os.makedirs("data", exist_ok=True)

    total = 0

    print("=" * 60)
    print("  NimHunter — Web Malware Fetcher")
    print("=" * 60)

    if args.hashes:
        bazaar_key = ""
        if os.path.exists(".bazaar_api_key"):
            bazaar_key = open(".bazaar_api_key").read().strip()
        total += fetch_from_hashlist(args.hashes, bazaar_key)

    if args.source in ("all", "thezoo"):
        total += fetch_thezoo()

    if args.source in ("all", "github"):
        total += fetch_github_repos(args.limit)

    if args.source in ("all", "vxug"):
        total += fetch_vxug()

    # Always print manual guide
    print_manual_guide()

    all_mal = sum(
        len([f for f in os.listdir(os.path.join(MALWARE_DIR, d))
             if f.endswith(".exe")])
        for d in os.listdir(MALWARE_DIR)
        if os.path.isdir(os.path.join(MALWARE_DIR, d))
    ) + len([f for f in os.listdir(MALWARE_DIR)
             if f.endswith(".exe") and os.path.isfile(os.path.join(MALWARE_DIR, f))])

    print(f"\n{'='*60}")
    print(f"  Total web samples fetched: {total}")
    print(f"  Total malware in dataset:  {all_mal}")
    print(f"{'='*60}")

    if total > 0:
        print("\nNext — retrain with new samples:")
        print("  .venv/bin/python3.13 scripts/extract_features.py")
        print("  .venv/bin/python3.13 scripts/train_model.py")

if __name__ == "__main__":
    main()
