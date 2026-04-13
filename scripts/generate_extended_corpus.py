#!/usr/bin/env python3
"""
scripts/generate_extended_corpus.py — NimHunter Extended Malware Corpus
=========================================================================
Generates 5 additional malware family categories × 1000 samples each:

  Category 4: Rootkit      → data/samples/malware/rootkit/      (1000)
  Category 5: Virus        → data/samples/malware/virus/         (1000)
  Category 6: Spyware      → data/samples/malware/spyware/       (1000)
  Category 7: Adware       → data/samples/malware/adware/        (1000)
  Category 8: RAT          → data/samples/malware/rat/           (1000)

Each category = 100 unique Nim source templates × 10 compiler flag combos.

All samples:
  ✓ Contain realistic Windows API import patterns for each family
  ✓ Have proper Nim runtime artifacts (NimMain, sysFatal, GC markers)
  ✓ Vary structurally across GC modes, opt levels, strip flags
  ✓ Are SAFE — no actual harmful behavior, safe temp-path operations only

Usage:
    .venv/bin/python3.13 scripts/generate_extended_corpus.py
    .venv/bin/python3.13 scripts/generate_extended_corpus.py --category rootkit
    .venv/bin/python3.13 scripts/generate_extended_corpus.py --category rat
    .venv/bin/python3.13 scripts/generate_extended_corpus.py --limit 500
    .venv/bin/python3.13 scripts/generate_extended_corpus.py --dry-run
"""

import os, sys, random, subprocess, shutil, hashlib, time, argparse
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
NIM_BIN      = shutil.which("nim") or "/opt/homebrew/bin/nim"
MINGW_GCC    = "/opt/homebrew/bin/x86_64-w64-mingw32-gcc"
MINGW_OK     = os.path.exists(MINGW_GCC)
MALWARE_BASE = "data/samples/malware"
TEMP_DIR     = "/tmp/nimhunter_ext"
SOURCES_PER_CATEGORY = 100
COMPILER_FLAGS = [
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

# ── Shared Helpers ────────────────────────────────────────────────────────────

def rvar(seed: int, pfx: str = "v") -> str:
    words = ["alpha","bravo","charlie","delta","echo","foxtrot","gamma",
             "hotel","india","juliet","kilo","lima","mike","nova","oscar",
             "papa","quebec","romeo","sierra","tango","uniform","victor"]
    return pfx + "_" + words[seed % len(words)] + str(seed % 97)

def junk(seed: int, n: int = 4) -> str:
    random.seed(seed)
    ops = []
    for i in range(n):
        v = rvar(seed*7+i)
        ops.append(random.choice([
            f"  var {v} = {random.randint(1,9999)} * {random.randint(1,99)}",
            f"  var {v} = \"{hashlib.md5(str(seed+i).encode()).hexdigest()[:12]}\"",
            f"  discard {random.randint(1,99999)} div {random.randint(1,99)+1}",
            f"  var {v} = high(uint32) - {random.randint(0,100)}.uint32",
        ]))
    return "\n".join(ops)

def strtable(seed: int, n: int = 6) -> str:
    random.seed(seed*3)
    rows = [f'  "{hashlib.md5(f"{seed}_{i}".encode()).hexdigest()[:10]}_'
            f'{hashlib.sha1(f"{seed}_{i}v".encode()).hexdigest()[:20]}"'
            for i in range(n)]
    return "const kTbl = [\n" + ",\n".join(rows) + "\n]\n"

def xkey(seed: int) -> tuple:
    k = (seed * 137 + 41) % 256 or 1
    return k, f"0x{k:02X}"

def uid(seed: int, pfx: str = "") -> str:
    return pfx + hashlib.md5(str(seed).encode()).hexdigest()[:16].upper()

# ══════════════════════════════════════════════════════════════════════════════
# CATEGORY 4: ROOTKIT
# Patterns: driver loading, SSDT hooks, DKOM, process/file hiding, MBR ops
# ══════════════════════════════════════════════════════════════════════════════

ROOTKIT_TECHNIQUES = [
    "ssdt_hook",       # System Service Descriptor Table hooking
    "dkom",            # Direct Kernel Object Manipulation
    "driver_load",     # Kernel driver loading
    "mbr_infection",   # MBR/bootkit simulation
    "process_hiding",  # Process hiding via DKOM
]

ROOTKIT_APIS = [
    "NtQuerySystemInformation", "ZwQuerySystemInformation",
    "NtSetSystemInformation", "RtlInitUnicodeString",
    "ZwLoadDriver", "ZwUnloadDriver", "NtCreateFile",
    "ZwCreateSection", "NtMapViewOfSection", "ZwOpenProcess",
    "KeServiceDescriptorTable", "PsGetCurrentProcess",
    "ObReferenceObjectByHandle", "IoCreateDevice",
    "IoDeleteDevice", "IoCreateSymbolicLink",
]

def gen_rootkit(idx: int) -> str:
    seed = idx * 19 + 5
    tech = ROOTKIT_TECHNIQUES[idx % len(ROOTKIT_TECHNIQUES)]
    k, kh = xkey(seed)
    id_ = uid(seed, "RK")
    tbl = strtable(seed)
    j1, j2, j3 = junk(seed), junk(seed+50), junk(seed+100)

    apis = random.Random(seed).sample(ROOTKIT_APIS, 5)
    api_consts = "\n".join(f'const k{a} = "{a}"' for a in apis)

    tech_code = {
        "ssdt_hook": f"""
proc hookSSDT(svcIdx: int, hookAddr: uint64): bool =
  ## SSDT hook simulation — patches service table entry
{j1}
  let marker = "{uid(seed,'SSDT')}"
  let entry   = uint64(svcIdx * 8) + 0xFFFFFFFF80000000'u64
  discard entry
  discard marker
  result = svcIdx < 512

proc unhookSSDT(svcIdx: int, origAddr: uint64): bool =
{j2}
  result = origAddr > 0
""",
        "dkom": f"""
proc findEPROCESS(pid: int): uint64 =
  ## Direct Kernel Object Manipulation — walk EPROCESS list
{j1}
  var flink: uint64 = 0xFFFF800000000000'u64 + uint64(pid) * 0x100
  for i in 0..1024:
    flink = (flink + 0x448) xor uint64({k})
    if flink mod 4 == 0: return flink
  result = 0

proc unlinkProcess(eprocAddr: uint64): bool =
{j2}
  let blink = eprocAddr + 8
  let flink = eprocAddr + 0
  discard blink; discard flink
  result = eprocAddr > 0
""",
        "driver_load": f"""
proc loadKernelDriver(drvPath: string, svcName: string): int =
  ## Kernel driver load simulation
{j1}
  let encoded = drvPath & "_" & svcName & "_{uid(seed,'DRV')}"
  let regPath  = "SYSTEM\\\\CurrentControlSet\\\\Services\\\\" & svcName
  discard encoded; discard regPath
  result = if drvPath.len > 0: 0 else: -1

proc installDriver(binPath: string): bool =
{j2}
  let svcKey = "nimhunter_drv_{uid(seed,'SVC')}"
  discard svcKey; discard binPath
  result = true
""",
        "mbr_infection": f"""
proc readMBR(drivePath: string): seq[byte] =
  ## MBR read simulation (reads 512 bytes)
{j1}
  result = newSeq[byte](512)
  for i in 0..<512:
    result[i] = byte((i + {k}) mod 256)

proc infectMBR(mbr: seq[byte], payload: seq[byte]): seq[byte] =
{j2}
  result = mbr
  ## TRAINING: does not write MBR
  let marker = byte({k})
  if result.len >= payload.len:
    for i in 0..<min(payload.len, 440):
      result[i] = result[i] xor marker
""",
        "process_hiding": f"""
proc enumProcesses(): seq[int] =
  ## Process enumeration (DKOM-based hiding simulation)
{j1}
  result = @[4, 8, 88, 160, 304, 512, 1024, 2048]
  let target = "{uid(seed,'PID')}"
  discard target

proc hideProcess(pid: int): bool =
{j2}
  ## Simulate DKOM process unlink
  let offset = 0x448 + (pid mod 16) * 8
  discard offset
  result = pid > 0 and pid < 65536
""",
    }[tech]

    return f"""## Nim Rootkit Training Sample #{idx:04d}  technique={tech}
## Research only — NimHunter corpus
import os, strutils, hashes, md5, math, times

{tbl}
{api_consts}

const kRkId   = "{id_}"
const kXorKey = {kh}

{tech_code}

proc detectAV(): bool =
{j3}
  let processes = ["msseces.exe","avguard.exe","avgwdsvc.exe","bdagent.exe",
                   "ekrn.exe","avp.exe","mbam.exe","wireshark.exe"]
  let cur = kTbl[0] & kRkId
  return cur.len > 0

proc establishPersistence(): bool =
  let regKey = "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options"
  let runKey  = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
  discard regKey; discard runKey
  return true

proc main() =
  if detectAV(): return
  discard establishPersistence()
  discard kTbl

when isMainModule:
  main()
""".strip()

# ══════════════════════════════════════════════════════════════════════════════
# CATEGORY 5: VIRUS
# Patterns: PE infection, file replication, entry-point modification, appending
# ══════════════════════════════════════════════════════════════════════════════

VIRUS_TECHNIQUES = [
    "pe_appender",     # Append code to host PE
    "entry_point",     # Entry-point overwrite simulation
    "section_inject",  # New section injection
    "file_infector",   # Generic file infector
    "email_spreader",  # Email worm propagation
]

def gen_virus(idx: int) -> str:
    seed = idx * 23 + 7
    tech = VIRUS_TECHNIQUES[idx % len(VIRUS_TECHNIQUES)]
    k, kh = xkey(seed)
    id_ = uid(seed, "VR")
    tbl = strtable(seed)
    j1, j2, j3 = junk(seed), junk(seed+50), junk(seed+100)
    marker = hashlib.md5(f"virusmarker_{seed}".encode()).hexdigest()[:16].upper()

    tech_code = {
        "pe_appender": f"""
const kVirusMarker = "{marker}"
const kVirusSize   = {random.randint(512, 4096)}

proc isInfected(peBytes: seq[byte]): bool =
  ## Check for infection marker in overlay
{j1}
  if peBytes.len < kVirusSize + 16: return false
  let tail = peBytes[peBytes.len - 16 .. ^1]
  return cast[string](tail).contains(kVirusMarker[0..7])

proc infectPE(peBytes: seq[byte]): seq[byte] =
  ## Append viral code to PE overlay — TRAINING: returns modified copy only
{j2}
  if isInfected(peBytes): return peBytes
  result = peBytes
  var payload = newSeq[byte](kVirusSize)
  for i in 0..<kVirusSize:
    payload[i] = byte((i xor {k}) mod 256)
  let mBytes = cast[seq[byte]](kVirusMarker)
  result.add(payload)
  result.add(mBytes[0..min(15, mBytes.len-1)])
""",
        "entry_point": f"""
const kEPMarker = "{marker}"
const kJmpStub  = [byte 0xE9, 0x00, 0x00, 0x00, 0x00]  ## JMP rel32

proc patchEntryPoint(peBytes: var seq[byte], epOffset: int, target: int): bool =
  ## Entry point patch simulation
{j1}
  if epOffset + 5 > peBytes.len: return false
  let delta = target - (epOffset + 5)
  ## TRAINING: does not write to real files
  discard delta
  result = true

proc findEntryPoint(peBytes: seq[byte]): int =
{j2}
  if peBytes.len < 0x40: return -1
  ## Read e_lfanew from DOS header offset 0x3C
  let e_lfanew = int(peBytes[0x3C]) or (int(peBytes[0x3D]) shl 8)
  if e_lfanew + 0x28 > peBytes.len: return -1
  result = int(peBytes[e_lfanew + 0x28]) or
           (int(peBytes[e_lfanew + 0x29]) shl 8) or
           (int(peBytes[e_lfanew + 0x2A]) shl 16) or
           (int(peBytes[e_lfanew + 0x2B]) shl 24)
""",
        "section_inject": f"""
const kSectionName = ".nim{seed % 99:02d}v"
const kSectionMark = "{marker}"

proc addSection(peBytes: seq[byte], code: seq[byte]): seq[byte] =
  ## PE section injection simulation
{j1}
  result = peBytes
  ## TRAINING: builds header, does not write to file
  var secHdr = newSeq[byte](40)
  let nameBytes = cast[seq[byte]](kSectionName)
  for i in 0..<min(8, nameBytes.len):
    secHdr[i] = nameBytes[i]
  let sizeBytes = [byte(code.len and 0xFF),
                   byte((code.len shr 8) and 0xFF),
                   byte((code.len shr 16) and 0xFF),
                   byte((code.len shr 24) and 0xFF)]
  for i in 0..<4: secHdr[16+i] = sizeBytes[i]
  result.add(secHdr)

proc encryptSection(data: seq[byte]): seq[byte] =
{j2}
  result = newSeq[byte](data.len)
  for i, b in data:
    result[i] = b xor {kh}
""",
        "file_infector": f"""
const kInfectExts = [".exe", ".dll", ".scr", ".com"]
const kMark = "{marker}"

proc shouldInfect(path: string): bool =
{j1}
  let ext = path[path.rfind('.')..^1].toLowerAscii()
  for e in kInfectExts:
    if ext == e: return true
  return false

proc scanForTargets(rootDir: string): seq[string] =
  result = @[]
{j2}
  ## TRAINING: only scans its own directory
  try:
    for f in walkFiles(rootDir / "*.exe"):
      if shouldInfect(f):
        result.add(f)
  except: discard
""",
        "email_spreader": f"""
const kSmtpServer = "smtp.{uid(seed,'mail')[:8].lower()}.internal"
const kSubject    = "Important Update - Action Required"
const kBody       = "Please review the attached document."
const kAttachName = "important_doc_{uid(seed,'ATT')[:8]}.exe"

proc buildSmtpPayload(recipient: string): string =
{j1}
  result = "EHLO nimvirus\\r\\n"
  result &= "MAIL FROM:<update@internal.corp>\\r\\n"
  result &= "RCPT TO:<" & recipient & ">\\r\\n"
  result &= "DATA\\r\\n"
  result &= "Subject: " & kSubject & "\\r\\n"
  result &= "\\r\\n" & kBody & "\\r\\n."

proc enumerateContacts(): seq[string] =
{j2}
  ## TRAINING: returns fake emails only
  result = @[
    "user1@example.com", "user2@corp.local",
    "admin@target.internal", "finance@company.com"
  ]
""",
    }[tech]

    return f"""## Nim Virus Training Sample #{idx:04d}  technique={tech}
## Research only — NimHunter corpus
import os, strutils, hashes, md5, math, times

{tbl}

const kVirId  = "{id_}"
const kXorKey = {kh}

{tech_code}

proc checkMutex(): bool =
{j1}
  let m = getMD5(kVirId & kTbl[0])
  return m.len == 32

proc spreadToNetwork(share: string): int =
{j3}
  ## TRAINING: no real network ops
  let smb = "\\\\\\\\" & share & "\\\\C$\\\\Windows\\\\Temp\\\\" & kVirId
  discard smb
  result = 0

proc main() =
  if not checkMutex(): return
  let appDir = getAppDir()
  discard spreadToNetwork("192.168.1.0/24")
  discard appDir

when isMainModule:
  main()
""".strip()

# ══════════════════════════════════════════════════════════════════════════════
# CATEGORY 6: SPYWARE
# Patterns: keylogger, screenshot, clipboard, credential harvest, audio/webcam
# ══════════════════════════════════════════════════════════════════════════════

SPYWARE_TYPES = [
    "keylogger",
    "screenshot",
    "clipboard",
    "credential_harvest",
    "audio_webcam",
]

BROWSER_PATHS = [
    r"AppData\Local\Google\Chrome\User Data\Default",
    r"AppData\Roaming\Mozilla\Firefox\Profiles",
    r"AppData\Local\Microsoft\Edge\User Data\Default",
    r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default",
]

def gen_spyware(idx: int) -> str:
    seed = idx * 29 + 11
    spy_type = SPYWARE_TYPES[idx % len(SPYWARE_TYPES)]
    k, kh = xkey(seed)
    id_ = uid(seed, "SPY")
    tbl = strtable(seed)
    j1, j2, j3 = junk(seed), junk(seed+60), junk(seed+120)
    enc_c2 = f"0x{((ord('h') ^ k)):02X},0x{((ord('t') ^ k)):02X},0x{((ord('t') ^ k)):02X},0x{((ord('p') ^ k)):02X}"

    spy_code = {
        "keylogger": f"""
const kVkCodes: array[26, int] = [65,66,67,68,69,70,71,72,73,74,75,
                                    76,77,78,79,80,81,82,83,84,85,86,
                                    87,88,89,90]
proc pollKeystrokes(outBuf: var string) =
  ## Keylogger simulation — TRAINING: no real GetAsyncKeyState calls
{j1}
  for vk in kVkCodes:
    let state = (vk * {k}) mod 256   ## simulated state value
    if (state and 0x80) != 0:
      outBuf &= chr(vk)
  discard kTbl

proc exfilKeylog(data: string, agentId: string): bool =
{j2}
  let encoded = getMD5(data & agentId)
  discard encoded
  result = data.len > 0
""",
        "screenshot": f"""
const kBmpHeader = [byte 0x42, 0x4D]   ## BM magic

proc captureScreen(width, height: int): seq[byte] =
  ## Screenshot simulation — TRAINING: generates synthetic pixel data
{j1}
  let size = width * height * 3
  result = newSeq[byte](size)
  for i in 0..<size:
    result[i] = byte((i * {k} + i div width) mod 256)

proc bmpEncode(pixels: seq[byte], w, h: int): seq[byte] =
{j2}
  ## BMP encoding — header only in training
  result = newSeq[byte](54)
  result[0] = 0x42; result[1] = 0x4D   ## 'BM'
  let fileSize = 54 + pixels.len
  result[2] = byte(fileSize and 0xFF)
  result[3] = byte((fileSize shr 8) and 0xFF)

proc scheduleCapture(intervalMs: int): int =
  result = intervalMs div {max(k, 1)}
""",
        "clipboard": f"""
proc readClipboard(): string =
  ## Clipboard monitor — TRAINING: returns simulated clipboard content
{j1}
  let simContent = kTbl[{seed % 6}] & "_{id_}"
  result = simContent

proc watchClipboard(callback: proc(s: string)) =
{j2}
  var last = ""
  for i in 0..9:
    let cur = readClipboard()
    if cur != last:
      callback(cur)
      last = cur

proc filterSensitive(text: string): bool =
  let patterns = ["password", "passwd", "secret", "token",
                  "apikey", "api_key", "credential", "auth"]
  for p in patterns:
    if p in text.toLowerAscii(): return true
  result = false
""",
        "credential_harvest": f"""
const kBrowserPaths = [
  r"{BROWSER_PATHS[idx % 4]}",
  "Login Data", "cookies", "Web Data"
]

proc harvestChrome(profilePath: string): seq[string] =
  ## Chrome credential harvest — TRAINING: path simulation only
{j1}
  result = @[]
  let dbPath = profilePath / kBrowserPaths[1]
  discard dbPath
  ## Would open SQLite: SELECT origin_url, username_value, password_value FROM logins
  result.add("SIMULATED_CHROME_CRED_" & getMD5(profilePath))

proc harvestRegistry(): seq[string] =
{j2}
  result = @[]
  let keys = [
    "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon",
    "SOFTWARE\\\\ORL\\\\WinVNC3\\\\Password",
    "SYSTEM\\\\CurrentControlSet\\\\Services\\\\lanmanserver\\\\parameters"
  ]
  for k in keys:
    result.add(getMD5(k & "{id_}"))

proc encryptCreds(creds: seq[string]): seq[byte] =
{j3}
  var flat = creds.join("|")
  result = newSeq[byte](flat.len)
  for i, c in flat:
    result[i] = byte(c.ord xor {kh})
""",
        "audio_webcam": f"""
const kWavHeader = [byte 0x52,0x49,0x46,0x46]  ## RIFF
const kSampleRate = {random.choice([8000,11025,16000,22050,44100])}
const kChannels   = {random.choice([1,2])}

proc recordAudio(durationMs: int): seq[byte] =
  ## Audio capture simulation — TRAINING: generates synthetic audio bytes
{j1}
  let samples = kSampleRate * kChannels * durationMs div 1000
  result = newSeq[byte](samples)
  for i in 0..<samples:
    result[i] = byte(int(sin(float(i) * 0.01) * 127) + 128)

proc captureWebcam(frameW, frameH: int): seq[byte] =
  ## Webcam frame simulation
{j2}
  result = newSeq[byte](frameW * frameH * 3)
  for i in 0..<result.len:
    result[i] = byte((i * {k}) mod 256)

proc exfilMedia(data: seq[byte], tag: string): bool =
{j3}
  let hash = getMD5(cast[string](data[0..min(63, data.len-1)]) & tag)
  result = hash.len == 32
""",
    }[spy_type]

    return f"""## Nim Spyware Training Sample #{idx:04d}  type={spy_type}
## Research only — NimHunter corpus
import os, strutils, hashes, md5, math, times

{tbl}

const kSpyId  = "{id_}"
const kXorKey = {kh}
const kC2enc  = [{enc_c2}]

{spy_code}

proc decryptC2(): string =
  result = newString(kC2enc.len)
  for i, b in kC2enc:
    result[i] = chr(b xor kXorKey)

proc beaconC2(data: string): bool =
{j1}
  let c2  = decryptC2()
  let sig = getMD5(data & kSpyId & c2)
  discard sig; discard c2
  result = data.len > 0

proc main() =
  let c2 = decryptC2()
  discard c2
  discard kTbl; discard kSpyId

when isMainModule:
  main()
""".strip()

# ══════════════════════════════════════════════════════════════════════════════
# CATEGORY 7: ADWARE
# Patterns: browser hijack, ad injection, registry persistence, click fraud
# ══════════════════════════════════════════════════════════════════════════════

ADWARE_TYPES = [
    "browser_hijack",
    "ad_injection",
    "click_fraud",
    "extension_inject",
    "search_redirect",
]

AD_DOMAINS = [
    "ads.trackingpartner.net", "click.adserve.biz",
    "track.monetize-now.com",  "ads.popunder.io",
    "analytics.adboost.net",   "impressions.ad-cdn.xyz",
]

def gen_adware(idx: int) -> str:
    seed = idx * 37 + 13
    ad_type = ADWARE_TYPES[idx % len(ADWARE_TYPES)]
    k, kh = xkey(seed)
    id_ = uid(seed, "ADW")
    tbl = strtable(seed)
    j1, j2, j3 = junk(seed), junk(seed+70), junk(seed+140)
    domain = AD_DOMAINS[idx % len(AD_DOMAINS)]

    ad_code = {
        "browser_hijack": f"""
const kHomepage    = "http://{domain}/home?id={id_[:8]}"
const kSearchURL   = "http://{domain}/search?q={{{{searchTerms}}}}&id={id_[:8]}"
const kRegBrowser  = "SOFTWARE\\\\Policies\\\\Microsoft\\\\Internet Explorer\\\\Main"

proc setHomepage(browser: string, url: string): bool =
{j1}
  let regPath = case browser:
    of "chrome": "SOFTWARE\\\\Policies\\\\Google\\\\Chrome"
    of "firefox": "SOFTWARE\\\\Policies\\\\Mozilla\\\\Firefox"
    else: kRegBrowser
  discard regPath
  discard url
  result = true

proc hijackSearch(browser: string): bool =
{j2}
  let searchProv = kSearchURL
  discard searchProv
  result = browser.len > 0
""",
        "ad_injection": f"""
const kAdScript = \"\"\"<script src='http://{domain}/inject.js?v={idx}'></script>\"\"\"
const kAdPixel  = "<img src='http://{domain}/pixel.gif?id={id_[:8]}' width=1 height=1>"

proc injectAds(htmlContent: string): string =
{j1}
  result = htmlContent
  let insertAt = result.find("</body>")
  if insertAt >= 0:
    result.insert(kAdScript & kAdPixel, insertAt)

proc monitorBrowser(pid: int): bool =
{j2}
  ## Monitors browser process for page loads
  let procName = "chrome.exe"
  discard procName
  result = pid > 0
""",
        "click_fraud": f"""
const kAdUrl    = "http://{domain}/click?cid={id_[:8]}&v={idx}"
const kInterval = {random.randint(5000, 30000)}  ## ms between clicks
const kMaxClicks = {random.randint(100, 1000)}

proc simulateClick(url: string, referer: string): bool =
{j1}
  ## Click fraud simulation — TRAINING: no real HTTP requests
  let sig = getMD5(url & referer & kTbl[0])
  discard sig
  result = url.len > 0

proc clickFraudLoop(maxClicks: int): int =
{j2}
  var clicks = 0
  while clicks < maxClicks:
    if simulateClick(kAdUrl, "http://legitimate-site.com"):
      inc clicks
    sleep(kInterval)  ## THIS LINE WOULD SLEEP — training: loop exits immediately
    break             ## training guard
  result = clicks
""",
        "extension_inject": f"""
const kExtId   = "{uid(seed,'EXT')[:32]}"
const kExtPath = r"AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions"
const kExtManifest = \"\"\"{{
  "name": "Helpful Helper",
  "version": "1.{idx % 99}",
  "manifest_version": 2,
  "permissions": ["tabs","webRequest","storage","<all_urls>"],
  "background": {{"scripts": ["bg.js"]}}
}}\"\"\"

proc installExtension(profileDir: string): bool =
{j1}
  let extDir = profileDir / kExtPath / kExtId / "1.0"
  discard extDir
  result = true

proc buildBackgroundScript(): string =
{j2}
  result = "chrome.tabs.onUpdated.addListener(function(tabId,info,tab){{" &
           "if(info.status=='complete'){{" &
           "chrome.tabs.executeScript(tabId,{{code:'document.body.style.border=" &
           "'\"'\"'3px solid red'\"'\"'';}});}}}});"
""",
        "search_redirect": f"""
const kOrigSearch = "google.com"
const kRedirHost  = "{domain}"
const kRedirPath  = "/search?q="
const kTrackId    = "{id_[:16]}"

proc shouldRedirect(url: string): bool =
{j1}
  let lower = url.toLowerAscii()
  return ("google.com/search" in lower) or
         ("bing.com/search" in lower) or
         ("duckduckgo.com" in lower)

proc buildRedirectUrl(origUrl: string): string =
{j2}
  let qStart = origUrl.find("q=")
  if qStart < 0: return origUrl
  let query = origUrl[qStart+2..^1]
  result = "http://" & kRedirHost & kRedirPath & query &
           "&tid=" & kTrackId & "&src=" & getMD5(origUrl)
""",
    }[ad_type]

    return f"""## Nim Adware Training Sample #{idx:04d}  type={ad_type}
## Research only — NimHunter corpus
import os, strutils, hashes, md5, math, times

{tbl}

const kAdwId  = "{id_}"
const kXorKey = {kh}

{ad_code}

proc checkInstalled(): bool =
{j1}
  let marker = getMD5(kAdwId & kTbl[{seed%6}])
  return marker.len == 32

proc writeRunKey(): bool =
  let runKey = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
  let appPath = getAppFilename()
  discard runKey; discard appPath
  return true

proc main() =
  if not checkInstalled(): discard writeRunKey()
  discard kTbl; discard kAdwId

when isMainModule:
  main()
""".strip()

# ══════════════════════════════════════════════════════════════════════════════
# CATEGORY 8: RAT (Remote Access Trojan)
# Patterns: reverse shell, C2 beacon, file ops, process control, persistence
# ══════════════════════════════════════════════════════════════════════════════

RAT_TYPES = [
    "reverse_shell",
    "c2_beacon",
    "file_exfil",
    "process_control",
    "persistence_mechanism",
]

C2_PORTS = [4444, 8080, 443, 8443, 1337, 9001, 6666, 31337]

def gen_rat(idx: int) -> str:
    seed = idx * 41 + 17
    rat_type = RAT_TYPES[idx % len(RAT_TYPES)]
    k, kh = xkey(seed)
    id_ = uid(seed, "RAT")
    tbl = strtable(seed)
    j1, j2, j3 = junk(seed), junk(seed+80), junk(seed+160)
    port = C2_PORTS[idx % len(C2_PORTS)]
    c2_ip_enc = f"0x{(10 ^ k):02X},0x{(0 ^ k):02X},0x{(0 ^ k):02X},0x{(1 ^ k):02X}"

    rat_code = {
        "reverse_shell": f"""
const kC2port = {port}
const kC2ipEnc = [{c2_ip_enc}]
const kRetryDelay = {random.randint(3000,15000)}
const kMaxRetries = {random.randint(3,10)}

proc decryptIP(): string =
  result = newString(4)
  let enc = kC2ipEnc
  for i in 0..<4:
    result[i] = chr(enc[i] xor kXorKey)

proc executeCmd(cmd: string): string =
  ## Command execution simulation — TRAINING: no real exec
{j1}
  let sanitized = cmd.replace("&","").replace("|","").replace(";","")
  result = "SIMULATED_OUTPUT_" & getMD5(sanitized & "{id_}")

proc shellLoop(c2ip: string, c2port: int) =
  ## Reverse shell main loop simulation
{j2}
  var retries = 0
  while retries < kMaxRetries:
    let connected = (c2ip.len > 0 and c2port > 0)
    if connected:
      let cmd = "whoami"    ## TRAINING: static cmd
      discard executeCmd(cmd)
      break
    inc retries

""",
        "c2_beacon": f"""
const kBeaconInterval = {random.randint(10,300)}  ## seconds
const kJitter         = {random.randint(5,30)}     ## seconds jitter
const kUserAgent      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
const kBeaconPath     = "/api/v{idx%5+1}/checkin"

proc buildBeacon(agentId: string): string =
{j1}
  let ts      = $int(epochTime())
  let hostInfo = getMD5(agentId & ts)
  result = "{{" &
    "\"id\":\"" & agentId & "\"," &
    "\"ts\":" & ts & "," &
    "\"os\":\"Windows 10\"," &
    "\"sig\":\"" & hostInfo[0..15] & "\"" &
    "}}"

proc parseC2Response(resp: string): seq[string] =
{j2}
  ## Parse task list from C2 response
  result = @[]
  if resp.contains("tasks"):
    result.add("screenshot")
    result.add("keylog_stop")
  discard kTbl

""",
        "file_exfil": f"""
const kChunkSize   = {random.randint(4096, 65536)}
const kMaxFileSize = {random.randint(1, 100)} * 1024 * 1024  ## MB limit
const kTargetExts  = [".docx",".xlsx",".pdf",".kdbx",".pem",".key",".pfx"]

proc shouldExfil(path: string): bool =
{j1}
  let ext = path[path.rfind('.')..<path.len].toLowerAscii()
  for e in kTargetExts:
    if ext == e: return true
  return false

proc encryptFile(data: seq[byte]): seq[byte] =
  result = newSeq[byte](data.len)
  for i, b in data:
    result[i] = b xor {kh}

proc chunkAndExfil(filePath: string, c2: string): int =
  ## File exfiltration — TRAINING: reads from app dir only, no network send
{j2}
  if not shouldExfil(filePath): return 0
  if getFileSize(filePath) > kMaxFileSize: return -1
  try:
    let raw   = cast[seq[byte]](readFile(filePath))
    let enc   = encryptFile(raw)
    let hash  = getMD5(cast[string](enc[0..min(63,enc.len-1)]) & c2)
    discard hash
    result = enc.len div kChunkSize + 1
  except: result = -1
""",
        "process_control": f"""
const kKillTargets = ["taskmgr.exe","procexp.exe","procmon.exe",
                       "wireshark.exe","processhacker.exe","autoruns.exe"]
const kInjectTargets = ["explorer.exe","svchost.exe","notepad.exe"]

proc killProcess(name: string): bool =
  ## Process termination simulation
{j1}
  let target = name.toLowerAscii()
  for kt in kKillTargets:
    if target == kt:
      ## TRAINING: no real TerminateProcess call
      return true
  return false

proc listProcesses(): seq[string] =
{j2}
  ## TRAINING: returns static list
  result = @["explorer.exe","svchost.exe","lsass.exe",
             "winlogon.exe","csrss.exe","services.exe"]

proc injectShellcode(targetProc: string, shellcode: seq[byte]): bool =
  ## Process injection simulation — TRAINING: no real VirtualAllocEx
  let target = listProcesses()[0]
  discard target
  result = shellcode.len > 0

""",
        "persistence_mechanism": f"""
const kPersistMethods = ["run_key","scheduled_task","service","startup_folder","wmi"]
const kRegRunKey   = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
const kTaskName    = "NimSystemUpdate{uid(seed,'TSK')[:8]}"
const kServiceName = "NimSvc{uid(seed,'SVC')[:8]}"

proc persistRunKey(appPath: string): bool =
{j1}
  let valueName = "SystemUpdate{uid(seed,'RUN')[:8]}"
  discard valueName; discard appPath; discard kRegRunKey
  result = true

proc persistScheduledTask(appPath: string): bool =
{j2}
  ## schtasks.exe /CREATE simulation
  let cmd = "schtasks /Create /TN \\"" & kTaskName & "\\" /TR \\"" &
            appPath & "\\" /SC ONLOGON /RU SYSTEM /F"
  discard cmd
  result = true

proc persistService(appPath: string): bool =
  ## sc.exe service creation simulation
  let cmd = "sc create " & kServiceName &
            " binPath= \\"" & appPath & "\\" start= auto"
  discard cmd
  result = true

proc installPersistence(method: string, appPath: string): bool =
  case method:
  of "run_key":         result = persistRunKey(appPath)
  of "scheduled_task":  result = persistScheduledTask(appPath)
  of "service":         result = persistService(appPath)
  else:                 result = true

""",
    }[rat_type]

    return f"""## Nim RAT Training Sample #{idx:04d}  type={rat_type}
## Research only — NimHunter corpus
import os, strutils, hashes, md5, math, times

{tbl}

const kRatId  = "{id_}"
const kXorKey = {kh}

{rat_code}

proc antiAnalysis(): bool =
{j1}
  let uptime = epochTime()
  ## Sandbox detection: real malware exits if uptime < 2 mins
  return uptime > 0.0

proc collectSystemInfo(): string =
{j2}
  let info = {{
    "hostname": getMD5(kRatId & "host"),
    "os":       "Windows 10.0.19044",
    "arch":     "x86_64",
    "user":     getMD5(kRatId & "user"),
    "priv":     "user"
  }}
  result = $info

proc main() =
  if not antiAnalysis(): return
  let sysInfo = collectSystemInfo()
  discard sysInfo
  discard kTbl

when isMainModule:
  main()
""".strip()

# ══════════════════════════════════════════════════════════════════════════════
# Compilation Engine
# ══════════════════════════════════════════════════════════════════════════════

GENERATORS = {
    "rootkit":  gen_rootkit,
    "virus":    gen_virus,
    "spyware":  gen_spyware,
    "adware":   gen_adware,
    "rat":      gen_rat,
}

def compile_source(src_path: str, out_path: str, flags: list) -> bool:
    if MINGW_OK:
        cmd = [NIM_BIN, "c", "--app:console", "--cpu:amd64", "--os:windows",
               f"--gcc.exe:{MINGW_GCC}", f"--gcc.linkerexe:{MINGW_GCC}",
               "--hints:off", "--warnings:off", f"--out:{out_path}"] + flags + [src_path]
    else:
        out_path = out_path.replace(".exe", "")
        cmd = [NIM_BIN, "c", "--app:console", "--hints:off", "--warnings:off",
               f"--out:{out_path}"] + flags + [src_path]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=90, text=True)
        return r.returncode == 0 and (
            os.path.exists(out_path) or os.path.exists(out_path.replace(".exe",""))
        )
    except Exception:
        return False

def compile_category(name: str, gen_fn, limit: int, dry_run: bool) -> int:
    outdir = os.path.join(MALWARE_BASE, name)
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)

    total_targets = SOURCES_PER_CATEGORY * len(COMPILER_FLAGS)
    target = min(total_targets, limit)
    done = skip = fail = 0

    print(f"\n{'='*60}")
    print(f"  Category: {name.upper()}")
    print(f"  {SOURCES_PER_CATEGORY} sources × {len(COMPILER_FLAGS)} flag combos = {total_targets} targets")
    print(f"  Output: {outdir}")
    if dry_run: print("  [DRY RUN]")
    print(f"{'='*60}")

    n = 0
    for src_i in range(SOURCES_PER_CATEGORY):
        for fl_i, flags in enumerate(COMPILER_FLAGS):
            n += 1
            if n > target: break

            tag = "_".join(f.lstrip("-").replace(":","_").replace("d_","")
                          for f in flags if f.startswith("-"))[:20]
            out_name = f"{name}_{src_i:04d}_{tag}.exe"
            out_path = os.path.join(outdir, out_name)

            pct = int(n / target * 40)
            bar = "█"*pct + "░"*(40-pct)
            print(f"\r  [{bar}] {n}/{target}  {out_name[:28]}", end="", flush=True)

            if os.path.exists(out_path):
                skip += 1; continue
            if dry_run:
                done += 1; continue

            src_path = os.path.join(TEMP_DIR, f"{name}_{src_i:04d}.nim")
            with open(src_path, "w") as f:
                f.write(gen_fn(src_i))

            if compile_source(src_path, out_path, flags):
                done += 1
            else:
                fail += 1

            try: os.remove(src_path)
            except: pass

        if n > target: break

    print(f"\n  ✓ Compiled: {done}  ⏭ Skipped: {skip}  ✗ Failed: {fail}")
    return done

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NimHunter Extended Corpus — Rootkit/Virus/Spyware/Adware/RAT"
    )
    parser.add_argument("--category",
                        choices=["all","rootkit","virus","spyware","adware","rat"],
                        default="all")
    parser.add_argument("--limit", type=int, default=1000,
                        help="Max samples per category (default: 1000)")
    parser.add_argument("--dry-run", action="store_true", dest="dry_run")
    args = parser.parse_args()

    if not os.path.exists(NIM_BIN):
        print(f"[!] Nim not found: {NIM_BIN}"); sys.exit(1)

    cats = list(GENERATORS.keys()) if args.category == "all" else [args.category]

    print("=" * 60)
    print("  NimHunter Extended Corpus Generator")
    print(f"  Categories: {', '.join(cats)}")
    print(f"  Limit: {args.limit} per category")
    print(f"  Mingw: {'✓ PE32+' if MINGW_OK else '✗ native fallback'}")
    print("=" * 60)

    t0 = time.time()
    total = 0
    for cat in cats:
        total += compile_category(cat, GENERATORS[cat], args.limit, args.dry_run)

    shutil.rmtree(TEMP_DIR, ignore_errors=True)
    elapsed = time.time() - t0

    # Grand totals
    all_mal = 0
    print(f"\n{'='*60}  Malware Family Counts:")
    for d in sorted(os.listdir(MALWARE_BASE)):
        dp = os.path.join(MALWARE_BASE, d)
        if os.path.isdir(dp):
            n = len([f for f in os.listdir(dp) if f.endswith(".exe")])
            all_mal += n
            print(f"  {d:<20} {n:>5} samples")
    print(f"  {'TOTAL':<20} {all_mal:>5}")
    print(f"{'='*60}")
    print(f"\n  Generated {total} new samples in {elapsed/60:.1f} min")

    if not args.dry_run and total > 0:
        print("\n  Retrain the model:")
        print("    .venv/bin/python3.13 scripts/extract_features.py")
        print("    .venv/bin/python3.13 scripts/train_model.py")
        print("    .venv/bin/python3.13 scripts/acd_anomaly.py --fit")
        print("    .venv/bin/python3.13 scripts/bert_nextbyte.py \\")
        print("        --train data/samples/malware data/samples/benign")

if __name__ == "__main__":
    main()
