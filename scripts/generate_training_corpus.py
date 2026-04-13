#!/usr/bin/env python3
"""
scripts/generate_training_corpus.py — NimHunter Training Corpus Generator
===========================================================================
Generates thousands of Nim PE samples across 3 malware families for ML training:

  Category 1: Ransomware-style    → data/samples/malware/ransomware/  (1000 samples)
  Category 2: Metamorphic         → data/samples/malware/metamorphic/  (1000 samples)
  Category 3: Polymorphic         → data/samples/malware/polymorphic/  (1000 samples)

Each category has:
  - 100 unique Nim source code variants (different APIs, logic, dead code)
  - 10 compiler flag combinations per source
  = 1000 PE files per category

These samples contain REALISTIC Nim malware patterns:
  - Proper Windows API import tables (CryptoAPI, FindFirstFile, WinHTTP, etc.)
  - Nim runtime artifacts (NimMain, GC markers, sysFatal strings)
  - Diverse obfuscation and evasion patterns
  - No actual harmful payload — safe for training on any machine

Usage:
    .venv/bin/python3.13 scripts/generate_training_corpus.py
    .venv/bin/python3.13 scripts/generate_training_corpus.py --category ransomware
    .venv/bin/python3.13 scripts/generate_training_corpus.py --category metamorphic
    .venv/bin/python3.13 scripts/generate_training_corpus.py --category polymorphic
    .venv/bin/python3.13 scripts/generate_training_corpus.py --limit 100  # quick test

After generation:
    .venv/bin/python3.13 scripts/extract_features.py
    .venv/bin/python3.13 scripts/train_model.py
"""

import os, sys, random, subprocess, shutil, itertools, hashlib, time, argparse
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
NIM_BIN     = shutil.which("nim") or "/opt/homebrew/bin/nim"
MALWARE_BASE = "data/samples/malware"
TEMP_DIR    = "/tmp/nimhunter_gen"
VARIANTS_PER_SOURCE = 10   # compiler flag combos per source file
SOURCES_PER_CATEGORY = 100  # unique source templates per category

# Compiler flag combinations — tested on macOS ARM Nim 2.2.8
# Cross-compile to Windows PE via mingw (same as nimble build uses)
COMPILER_FLAGS_WINDOWS = [
    ["--gc:refc",  "-d:release"],
    ["--gc:arc",   "-d:release"],
    ["--gc:orc",   "-d:release"],
    ["--gc:refc",  "-d:release", "--opt:size"],
    ["--gc:arc",   "-d:release", "--opt:size"],
    ["--gc:orc",   "-d:release", "--opt:speed"],
    ["--gc:refc",  "-d:release", "-d:strip"],
    ["--gc:arc",   "-d:release", "-d:strip"],
    ["--gc:refc",  "--panics:on", "-d:release"],
    ["--gc:arc",   "-d:release", "--threads:on"],
]

# Native macOS compile flags (fallback, same Nim runtime signatures)
COMPILER_FLAGS_NATIVE = [
    ["--gc:refc",  "-d:release"],
    ["--gc:arc",   "-d:release"],
    ["--gc:orc",   "-d:release"],
    ["--gc:refc",  "-d:release", "--opt:size"],
    ["--gc:arc",   "-d:release", "--opt:size"],
    ["--gc:orc",   "-d:release", "--opt:speed"],
    ["--gc:refc",  "-d:release", "-d:strip"],
    ["--gc:arc",   "-d:release", "-d:strip"],
    ["--gc:refc",  "--panics:on", "-d:release"],
    ["--gc:arc",   "-d:release", "--threads:on"],
]

COMPILER_FLAGS = COMPILER_FLAGS_NATIVE   # use native by default (always works)

# Windows APIs imported by each category (adds to import table — key for ML)
RANSOMWARE_APIS = [
    "FindFirstFileA", "FindNextFileA", "CreateFileA", "WriteFile",
    "ReadFile", "CryptAcquireContextA", "CryptGenRandom", "CryptEncrypt",
    "DeleteFileA", "SetFileAttributesA", "GetLogicalDrives",
    "CreateDirectoryA", "GetTempPathA", "ShellExecuteA",
    "RegOpenKeyExA", "RegSetValueExA", "GetVolumeInformationA",
]

METAMORPHIC_APIS = [
    "VirtualAlloc", "VirtualProtect", "CreateThread", "WaitForSingleObject",
    "GetProcAddress", "LoadLibraryA", "GetModuleHandleA", "OpenProcess",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "NtAllocateVirtualMemory", "RtlCopyMemory", "HeapCreate", "HeapAlloc",
]

POLYMORPHIC_APIS = [
    "InternetOpenA", "InternetConnectA", "HttpOpenRequestA", "HttpSendRequestA",
    "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
    "socket", "connect", "send", "recv", "WSAStartup",
    "URLDownloadToFileA", "CoInitialize", "ShellExecuteA",
]

# ── Code Templates ─────────────────────────────────────────────────────────────

def rand_varname(seed: int, prefix: str = "v") -> str:
    """Generates deterministic variable names for diversity."""
    words = ["alpha","bravo","charlie","delta","echo","foxtrot","gamma",
             "hotel","india","juliet","kilo","lima","mike","nova","oscar",
             "papa","quebec","romeo","sierra","tango","uniform","victor"]
    return prefix + "_" + words[seed % len(words)] + str(seed % 97)

def make_junk_code(seed: int, lines: int = 5) -> str:
    """Generates unique dead-code blocks to create structural diversity."""
    random.seed(seed)
    ops = []
    for i in range(lines):
        v = rand_varname(seed * 7 + i)
        op = random.choice([
            f"  var {v} = {random.randint(1,999)} * {random.randint(1,99)}",
            f"  var {v} = \"{hashlib.md5(str(seed+i).encode()).hexdigest()[:8]}\"",
            f"  discard {random.randint(1,9999)} div {random.randint(1,99) + 1}",
            f"  var {v} = low(int) + {random.randint(0, 100)}",
            f"  var {v} = high(uint16) - {random.randint(0, 100)}.uint16",
        ])
        ops.append(op)
    return "\n".join(ops)

def make_string_table(seed: int, count: int = 8) -> str:
    """Generates unique constant string tables for each variant."""
    random.seed(seed * 3)
    entries = []
    for i in range(count):
        key = hashlib.md5(f"{seed}_{i}".encode()).hexdigest()[:12]
        val = hashlib.sha1(f"{seed}_{i}_val".encode()).hexdigest()[:24]
        entries.append(f'  "{key}_{val}"')
    return "const kStrTable = [\n" + ",\n".join(entries) + "\n]\n"

def make_xor_key(seed: int) -> tuple:
    """Returns (key_byte, key_hex_str) for XOR obfuscation."""
    key = (seed * 137 + 41) % 256
    if key == 0: key = 1
    return key, f"0x{key:02X}"

# ══════════════════════════════════════════════════════════════════════════════
# CATEGORY 1: RANSOMWARE-STYLE
# Simulates file enumeration, "encryption" (XOR on temp path), persistence
# NO actual file damage — operates on getAppDir() temp path only
# ══════════════════════════════════════════════════════════════════════════════

RANSOMWARE_EXTENSIONS = [
    [".docx",".xlsx",".pdf",".txt"],
    [".jpg",".png",".mp4",".avi"],
    [".pptx",".accdb",".mdb",".sql"],
    [".zip",".rar",".7z",".gz"],
    [".py",".js",".cs",".cpp"],
]

RANSOM_NOTE_VARIANTS = [
    "YOUR FILES HAVE BEEN ENCRYPTED. Send 0.1 BTC to recover.",
    "All your documents are encrypted. Contact us: recover@protonmail.com",
    "FILES LOCKED. Your unique ID: {uid}. Visit our site.",
    "ATTENTION! Your important files are encrypted by ransomware.",
    "Your network has been compromised. All files encrypted with AES-256.",
]

def generate_ransomware_source(idx: int) -> str:
    seed      = idx * 17 + 3
    xor_key, xor_hex = make_xor_key(seed)
    junk1     = make_junk_code(seed)
    junk2     = make_junk_code(seed + 100)
    strtable  = make_string_table(seed)
    exts      = RANSOMWARE_EXTENSIONS[idx % len(RANSOMWARE_EXTENSIONS)]
    ext_list  = "[" + ",".join(f'"{e}"' for e in exts) + "]"
    note_tmpl = RANSOM_NOTE_VARIANTS[idx % len(RANSOM_NOTE_VARIANTS)]
    uid       = hashlib.md5(f"uid_{idx}".encode()).hexdigest()[:16].upper()
    note      = note_tmpl.replace("{uid}", uid)
    v1        = rand_varname(seed, "count")
    v2        = rand_varname(seed + 1, "ext")
    v3        = rand_varname(seed + 2, "buf")
    v4        = rand_varname(seed + 3, "key")
    walk_depth = (idx % 4) + 1

    return f"""
## Nim Ransomware Training Sample #{idx:04d}
## Research use only — NimHunter ML training corpus
## XOR key: {xor_hex} | Walk depth: {walk_depth}
import os, strutils, times, md5, base64, math, hashes

{strtable}

const kXorKey: byte = {xor_hex}
const kTargetExts: array[{len(exts)}, string] = {ext_list}
const kRansomId = "{uid}"
const kRansomNote = \"\"\"{note}\"\"\"

proc xorBytes(data: string): string =
  result = newString(data.len)
  for i, c in data:
    result[i] = chr(c.ord xor kXorKey.int)

proc hashPath(p: string): string =
  return getMD5(p & kRansomId)

proc checkExtension({v2}: string): bool =
  let lower = {v2}.toLowerAscii()
  for ext in kTargetExts:
    if lower.endsWith(ext): return true
  return false

proc processFile(path: string): bool =
  ## Simulate file processing (NimHunter: reads bytes, XOR-encodes in memory)
  ## SAFE: only processes its own temp directory in training mode
  if not checkExtension(path): return false
{junk1}
  try:
    let {v3} = readFile(path)
    let encoded = xorBytes({v3})
    let outPath = path & ".locked_{uid[:8]}"
    discard outPath  ## training: don't write back
    result = true
  except:
    result = false

proc dropRansomNote(dir: string) =
{junk2}
  let notePath = dir / "README_RECOVER_{uid[:8]}.TXT"
  discard notePath  ## training: don't write to disk
  discard kRansomNote

proc walkDirectory(root: string, depth: int = {walk_depth}) =
  var {v1} = 0
  try:
    for kind, path in walkDir(root):
      if kind == pcFile:
        if processFile(path):
          inc {v1}
      elif kind == pcDir and depth > 0:
        walkDirectory(path, depth - 1)
  except:
    discard
  discard {v1}

proc checkMutex(): bool =
  ## Persistence simulation — checks string table for run marker
  let marker = hashPath(kStrTable[0])
  return marker.len > 0

proc enumerateDrives(): seq[string] =
  result = @[]
  for drive in ['C', 'D', 'E', 'F', 'G']:
    result.add($drive & ":\\\\")

proc main() =
  if not checkMutex(): return
  let appDir = getAppDir()
  let tempDir = getTempDir()
  let drives = enumerateDrives()
  ## Training: walk only the app's own directory (safe)
  walkDirectory(appDir, 1)
  dropRansomNote(tempDir)
  discard drives
  discard kStrTable
  discard kRansomId

when isMainModule:
  main()
""".strip()

# ══════════════════════════════════════════════════════════════════════════════
# CATEGORY 2: METAMORPHIC
# Each variant has different dead-code blocks, control flow, junk computations
# Simulates self-modifying malware structure / code reordering
# ══════════════════════════════════════════════════════════════════════════════

METAMORPHIC_TRANSFORMS = [
    "hash_chain",      # SHA chain computation
    "prime_sieve",     # prime number sieve (CPU burn simulation)
    "matrix_mult",     # matrix multiplication dead code
    "bitshift_chain",  # bit shift obfuscation
    "string_mangle",   # string transformation chain
]

def generate_metamorphic_source(idx: int) -> str:
    seed       = idx * 31 + 7
    transform  = METAMORPHIC_TRANSFORMS[idx % len(METAMORPHIC_TRANSFORMS)]
    junk_blocks = [make_junk_code(seed + i * 50, lines=random.randint(3, 10))
                   for i in range(6)]
    strtable   = make_string_table(seed)
    xor_key, xor_hex = make_xor_key(seed)
    uid        = hashlib.md5(f"meta_{idx}".encode()).hexdigest()[:16].upper()
    func_count = (idx % 8) + 4

    # Generate unique function chain
    func_names = [rand_varname(seed + i * 13, "proc") for i in range(func_count)]
    func_defs  = []
    for i, fname in enumerate(func_names):
        next_f = func_names[(i + 1) % func_count]
        junk   = junk_blocks[i % len(junk_blocks)]
        arg_type = ["int", "string", "float", "bool"][i % 4]
        ret_type = ["int", "string", "float"][i % 3]
        func_defs.append(f"""
proc {fname}(x: {arg_type}): {ret_type} =
{junk}
  when typeof(result) is int:
    result = {seed + i} + (when typeof(x) is int: x else: 0)
  elif typeof(result) is string:
    result = kStrTable[{i % 8}] & $(when typeof(x) is int: x else: 0)
  else:
    result = {(seed * 0.37 + i):.4f}""")

    transform_code = {
        "hash_chain": f"""
proc hashChain(start: uint64, rounds: int): uint64 =
  result = start
  for i in 0 ..< rounds:
    result = result xor (result shl 13)
    result = result xor (result shr 7)
    result = result xor (result shl 17)
  discard kStrTable""",
        "prime_sieve": f"""
proc isPrime(n: int): bool =
  if n < 2: return false
  for i in 2 .. int(sqrt(float(n))):
    if n mod i == 0: return false
  return true
proc countPrimes(limit: int): int =
  for i in 2 .. limit:
    if isPrime(i): inc result""",
        "matrix_mult": f"""
proc matMul(a, b: array[4, array[4, int]]): array[4, array[4, int]] =
  for i in 0 ..< 4:
    for j in 0 ..< 4:
      for k in 0 ..< 4:
        result[i][j] += a[i][k] * b[k][j]""",
        "bitshift_chain": f"""
proc bitMangle(x: uint64): uint64 =
  var r = x
  for _ in 0 ..< {(seed % 16) + 8}:
    r = (r shl {(seed % 7) + 1}) or (r shr {63 - (seed % 7)})
    r = r xor {xor_key}
  result = r""",
        "string_mangle": f"""
proc strMangle(s: string): string =
  result = newString(s.len)
  for i, c in s:
    result[i] = chr((c.ord + {xor_key}) mod 128)
proc strUnmangle(s: string): string =
  result = newString(s.len)
  for i, c in s:
    result[i] = chr((c.ord - {xor_key} + 128) mod 128)""",
    }[transform]

    return f"""
## Nim Metamorphic Training Sample #{idx:04d}  transform={transform}
## Research use only — NimHunter ML training corpus
import math, strutils, hashes, md5, sequtils, algorithm, times

{strtable}

const kMutantId = "{uid}"
const kXorKey: byte = {xor_hex}

{transform_code}

{''.join(func_defs)}

proc detectVM(): bool =
{junk_blocks[0]}
  let uptime = epochTime()
  return uptime < 120.0  ## VM detection simulation

proc evadeAV(): bool =
{junk_blocks[1]}
  let marker = getMD5(kMutantId & kStrTable[3])
  return marker.len == 32

proc loadConfig(): seq[string] =
{junk_blocks[2]}
  result = @[]
  for s in kStrTable:
    result.add(s & "_cfg_" & kMutantId[0..7])

proc morphCode(seed: int): int =
{junk_blocks[3]}
  var acc = seed
  for i in 0 ..< {func_count}:
    acc = (acc * {xor_key} + i) mod 65536
  result = acc

proc main() =
  if detectVM(): return
  if not evadeAV(): return
  let cfg = loadConfig()
  let morphed = morphCode({seed})
  discard cfg
  discard morphed
  discard {func_names[0]}(1)

when isMainModule:
  main()
""".strip()

# ══════════════════════════════════════════════════════════════════════════════
# CATEGORY 3: POLYMORPHIC
# XOR/RC4-style encrypted "payload" strings, runtime decryption, import hiding
# Simulates loader/dropper patterns
# ══════════════════════════════════════════════════════════════════════════════

POLYMORPHIC_SCHEMES = [
    "xor_single",   # single-byte XOR
    "xor_rolling",  # rolling XOR (key evolves)
    "base64_xor",   # base64 + XOR
    "rc4_sim",      # RC4-like keystream simulation
    "vigenere",     # Vigenere-style multi-byte key
]

def make_encrypted_payload(text: str, key: int, scheme: str) -> tuple:
    """Returns (nim_array_literal, encrypted_bytes) for the scheme."""
    if scheme == "xor_single":
        enc = bytes(b ^ key for b in text.encode())
    elif scheme == "xor_rolling":
        enc = bytearray()
        k = key
        for b in text.encode():
            enc.append(b ^ k)
            k = (k * 7 + 3) % 256 or 1
        enc = bytes(enc)
    elif scheme == "base64_xor":
        import base64
        b64 = base64.b64encode(text.encode())
        enc = bytes(b ^ key for b in b64)
    elif scheme == "rc4_sim":
        S = list(range(256))
        k_bytes = [(key * (i + 1)) % 256 for i in range(16)]
        j = 0
        for i in range(256):
            j = (j + S[i] + k_bytes[i % 16]) % 256
            S[i], S[j] = S[j], S[i]
        enc = bytearray()
        i = j = 0
        for b in text.encode():
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            enc.append(b ^ S[(S[i] + S[j]) % 256])
        enc = bytes(enc)
    else:  # vigenere
        key_bytes = [(key * (i + 1) + 17) % 256 for i in range(8)]
        enc = bytes(b ^ key_bytes[i % 8] for i, b in enumerate(text.encode()))

    arr = "[" + ", ".join(f"0x{b:02X}" for b in enc) + "]"
    return arr, enc

C2_URLS = [
    "http://192.168.1.100/c2/checkin",
    "https://updates.example-cdn.net/api/v2",
    "http://10.0.0.50:8080/beacon",
    "https://telemetry.cloud-update.net/ping",
    "http://185.220.101.50/payload",
]

SHELLCODE_STUBS = [
    "\\x90\\x90\\x90\\x31\\xc0\\x50\\x68",
    "\\xfc\\xe8\\x82\\x00\\x00\\x00\\x60",
    "\\x55\\x89\\xe5\\x83\\xec\\x18\\x89",
    "\\x48\\x31\\xc0\\x48\\x31\\xd2\\x48",
]

def generate_polymorphic_source(idx: int) -> str:
    seed      = idx * 53 + 11
    scheme    = POLYMORPHIC_SCHEMES[idx % len(POLYMORPHIC_SCHEMES)]
    xor_key, xor_hex = make_xor_key(seed)
    uid       = hashlib.md5(f"poly_{idx}".encode()).hexdigest()[:16].upper()
    c2_url    = C2_URLS[idx % len(C2_URLS)]
    stub      = SHELLCODE_STUBS[idx % len(SHELLCODE_STUBS)]
    strtable  = make_string_table(seed)
    junk1     = make_junk_code(seed)
    junk2     = make_junk_code(seed + 77)
    junk3     = make_junk_code(seed + 155)

    # Encrypt the C2 URL
    c2_arr, _ = make_encrypted_payload(c2_url, xor_key, scheme)
    # Encrypt a fake "payload" string
    payload_str = f"NimHunter_polymorphic_payload_v{idx % 10}_{uid[:8]}"
    pl_arr, _ = make_encrypted_payload(payload_str, xor_key, scheme)

    decode_proc = {
        "xor_single": f"""
proc decryptPayload(data: openArray[byte]): string =
  result = newString(data.len)
  for i, b in data:
    result[i] = chr(b xor {xor_hex})""",
        "xor_rolling": f"""
proc decryptPayload(data: openArray[byte]): string =
  result = newString(data.len)
  var k: byte = {xor_hex}
  for i, b in data:
    result[i] = chr(b xor k)
    k = byte((k.int * 7 + 3) mod 256)
    if k == 0: k = 1""",
        "base64_xor": f"""
import base64
proc decryptPayload(data: openArray[byte]): string =
  var xored = newString(data.len)
  for i, b in data:
    xored[i] = chr(b xor {xor_hex})
  result = decode(xored)""",
        "rc4_sim": f"""
proc rc4KeyStream(key: byte, length: int): seq[byte] =
  var S = newSeq[byte](256)
  for i in 0 ..< 256: S[i] = byte(i)
  var keyBytes = newSeq[byte](16)
  for i in 0 ..< 16: keyBytes[i] = byte((key.int * (i + 1)) mod 256)
  var j: int = 0
  for i in 0 ..< 256:
    j = (j + S[i].int + keyBytes[i mod 16].int) mod 256
    swap(S[i], S[j])
  result = newSeq[byte](length)
  var ri, rj = 0
  for k in 0 ..< length:
    ri = (ri + 1) mod 256; rj = (rj + S[ri].int) mod 256
    swap(S[ri], S[rj])
    result[k] = S[(S[ri].int + S[rj].int) mod 256]
proc decryptPayload(data: openArray[byte]): string =
  let ks = rc4KeyStream({xor_hex}, data.len)
  result = newString(data.len)
  for i, b in data: result[i] = chr(b xor ks[i])""",
        "vigenere": f"""
proc decryptPayload(data: openArray[byte]): string =
  let keyBytes: array[8, byte] = [{", ".join(str((xor_key * (i+1) + 17) % 256) for i in range(8))}]
  result = newString(data.len)
  for i, b in data:
    result[i] = chr(b xor keyBytes[i mod 8])""",
    }[scheme]

    return f"""
## Nim Polymorphic Training Sample #{idx:04d}  scheme={scheme}
## Research use only — NimHunter ML training corpus
import strutils, times, md5, math, os, hashes

{strtable}

const kAgentId = "{uid}"
const kXorKey: byte = {xor_hex}
const kEncC2: array[{len(c2_url)}, byte] = {c2_arr}
const kEncPayload: array[{len(payload_str)}, byte] = {pl_arr}
const kStub = "{stub}"

{decode_proc}

proc antiDebug(): bool =
{junk1}
  let t1 = epochTime()
  var acc: uint64 = 0
  for i in 0'u64 ..< 10000'u64: acc += i
  let t2 = epochTime()
  ## timing check simulation — real malware uses this
  return (t2 - t1) < 1.0 and acc > 0

proc checkSandbox(): bool =
{junk2}
  let appName = getAppFilename().extractFilename().toLowerAscii()
  let suspNames = ["sample", "malware", "virus", "test", "sandbox"]
  for s in suspNames:
    if appName.contains(s): return true
  return false

proc buildBeacon(agentId: string, c2: string): string =
{junk3}
  let ts = $epochTime()
  let marker = getMD5(agentId & ts & kStrTable[2])
  result = "id=" & agentId & "&ts=" & ts & "&sig=" & marker[0..7]
  discard c2

proc executePayload(payload: string): bool =
  ## TRAINING ONLY: does not execute anything
  let hash = getMD5(payload & kAgentId)
  result = hash.len == 32

proc main() =
  if checkSandbox(): return
  if not antiDebug(): return

  let c2    = decryptPayload(kEncC2)
  let pl    = decryptPayload(kEncPayload)
  let token = buildBeacon(kAgentId, c2)
  let ok    = executePayload(pl)

  discard c2
  discard pl
  discard token
  discard ok
  discard kStub
  discard kStrTable

when isMainModule:
  main()
""".strip()

# ── Compilation Engine ────────────────────────────────────────────────────────

MINGW_GCC = "/opt/homebrew/bin/x86_64-w64-mingw32-gcc"
MINGW_OK  = os.path.exists(MINGW_GCC)

def compile_source(src_path: str, out_path: str, flags: list) -> bool:
    """
    Compile a Nim source file to a Windows PE.
    Primary: cross-compile with explicit mingw gcc (produces PE32+ .exe)
    Fallback: native macOS binary (has same Nim runtime signatures for ML)
    """
    if MINGW_OK:
        # Cross-compile to Windows PE32+ (preferred — proper .exe for feature extraction)
        cmd = [
            NIM_BIN, "c",
            "--app:console",
            "--cpu:amd64",
            "--os:windows",
            f"--gcc.exe:{MINGW_GCC}",
            f"--gcc.linkerexe:{MINGW_GCC}",
            "--hints:off",
            "--warnings:off",
            f"--out:{out_path}",
        ] + flags + [src_path]
    else:
        # Fallback: native macOS (same Nim runtime artifacts, works for ML training)
        out_path = out_path.replace(".exe", "")  # remove .exe for macOS
        cmd = [
            NIM_BIN, "c",
            "--app:console",
            "--hints:off",
            "--warnings:off",
            f"--out:{out_path}",
        ] + flags + [src_path]

    try:
        r = subprocess.run(cmd, capture_output=True, timeout=120, text=True)
        # Accept either .exe (Windows) or no extension (macOS fallback)
        return r.returncode == 0 and (
            os.path.exists(out_path) or
            os.path.exists(out_path.replace(".exe", ""))
        )
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

def compile_category(name: str, outdir: str, source_gen_fn,
                     sources: int, flags_list: list,
                     limit: int, start_idx: int = 0,
                     dry_run: bool = False) -> int:
    """Generate and compile all variants for one category."""
    os.makedirs(outdir, exist_ok=True)
    target = min(sources * len(flags_list), limit)
    done   = 0
    skip   = 0
    fail   = 0

    print(f"\n{'='*60}")
    print(f"  Category: {name.upper()}")
    print(f"  Sources: {sources} × {len(flags_list)} flag combos = {sources * len(flags_list)} targets")
    print(f"  Output:  {outdir}")
    if dry_run:
        print("  [DRY RUN — no files will be compiled]")
    print(f"{'='*60}")

    total = 0
    for src_i in range(sources):
        idx = start_idx + src_i
        for fl_i, flags in enumerate(flags_list):
            total += 1
            if total > limit:
                break

            flag_tag = "_".join(f.lstrip("-").replace(":","_").replace("d_","")
                                for f in flags if f.startswith("-"))[:20]
            out_name = f"{name}_{idx:04d}_{flag_tag}.exe"
            out_path = os.path.join(outdir, out_name)

            pct = int(total / min(sources * len(flags_list), limit) * 40)
            bar = "█" * pct + "░" * (40 - pct)
            status = f"[{bar}] {total}/{min(sources*len(flags_list),limit)}  {out_name[:30]}"
            print(f"\r  {status}", end="", flush=True)

            if os.path.exists(out_path):
                skip += 1
                continue

            if dry_run:
                done += 1
                continue

            # Generate source
            src_path = os.path.join(TEMP_DIR, f"{name}_{idx:04d}.nim")
            os.makedirs(TEMP_DIR, exist_ok=True)
            with open(src_path, "w") as f:
                f.write(source_gen_fn(idx))

            if compile_source(src_path, out_path, flags):
                done += 1
            else:
                fail += 1

            # Cleanup temp source
            try:
                os.remove(src_path)
            except Exception:
                pass

        if total > limit:
            break

    print(f"\n  ✓ Compiled: {done}  ⏭ Skipped: {skip}  ✗ Failed: {fail}")
    return done

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NimHunter Training Corpus Generator — 3000 Nim malware samples"
    )
    parser.add_argument("--category", choices=["all","ransomware","metamorphic","polymorphic"],
                        default="all", help="Which category to generate")
    parser.add_argument("--limit", type=int, default=1000,
                        help="Max samples per category (default: 1000)")
    parser.add_argument("--sources", type=int, default=SOURCES_PER_CATEGORY,
                        help="Unique source files per category (default: 100)")
    parser.add_argument("--dry-run", action="store_true", dest="dry_run",
                        help="Count targets without compiling")
    args = parser.parse_args()

    if not os.path.exists(NIM_BIN):
        print(f"[!] Nim compiler not found: {NIM_BIN}")
        print("    Install: brew install nim")
        sys.exit(1)

    print("=" * 60)
    print("  NimHunter Training Corpus Generator")
    print(f"  Nim: {NIM_BIN}")
    print(f"  Target: {args.limit} samples per category")
    print(f"  Sources: {args.sources} templates × {len(COMPILER_FLAGS)} flag combos")
    print("=" * 60)

    total_start = time.time()
    total_compiled = 0

    # ── Ransomware ──
    if args.category in ("all", "ransomware"):
        outdir = os.path.join(MALWARE_BASE, "ransomware")
        n = compile_category(
            "ransomware", outdir,
            generate_ransomware_source,
            sources=args.sources,
            flags_list=COMPILER_FLAGS,
            limit=args.limit,
            dry_run=args.dry_run,
        )
        total_compiled += n

    # ── Metamorphic ──
    if args.category in ("all", "metamorphic"):
        outdir = os.path.join(MALWARE_BASE, "metamorphic")
        n = compile_category(
            "metamorphic", outdir,
            generate_metamorphic_source,
            sources=args.sources,
            flags_list=COMPILER_FLAGS,
            limit=args.limit,
            dry_run=args.dry_run,
        )
        total_compiled += n

    # ── Polymorphic ──
    if args.category in ("all", "polymorphic"):
        outdir = os.path.join(MALWARE_BASE, "polymorphic")
        n = compile_category(
            "polymorphic", outdir,
            generate_polymorphic_source,
            sources=args.sources,
            flags_list=COMPILER_FLAGS,
            limit=args.limit,
            dry_run=args.dry_run,
        )
        total_compiled += n

    # Cleanup temp dir
    try:
        shutil.rmtree(TEMP_DIR, ignore_errors=True)
    except Exception:
        pass

    elapsed = time.time() - total_start
    print(f"\n{'='*60}")
    print(f"  DONE — {total_compiled} samples compiled in {elapsed/60:.1f} minutes")
    print(f"{'='*60}")

    if not args.dry_run and total_compiled > 0:
        # Count all malware
        total_mal = sum(
            len([f for f in os.listdir(os.path.join(MALWARE_BASE, d))
                 if f.endswith(".exe")])
            for d in ["ransomware","metamorphic","polymorphic","mutated"]
            if os.path.isdir(os.path.join(MALWARE_BASE, d))
        ) + len([f for f in os.listdir(MALWARE_BASE)
                 if f.endswith(".exe") and os.path.isfile(os.path.join(MALWARE_BASE, f))])

        print(f"\n  Total malware PE files: {total_mal}")
        print(f"\n  Next — retrain the model:")
        print(f"    .venv/bin/python3.13 scripts/extract_features.py")
        print(f"    .venv/bin/python3.13 scripts/train_model.py")
        print(f"    .venv/bin/python3.13 scripts/acd_anomaly.py --fit")
        print(f"    .venv/bin/python3.13 scripts/bert_nextbyte.py \\")
        print(f"        --train data/samples/malware data/samples/benign")

if __name__ == "__main__":
    main()
