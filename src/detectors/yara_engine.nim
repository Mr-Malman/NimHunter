## yara_engine.nim
## YARA rule scanning engine for NimHunter v2
## Uses YARA CLI with graceful fallback; returns named rule matches for scoring

import os, osproc, strutils

type
  YaraResult* = object
    matched*:     bool
    matchCount*:  int
    ruleNames*:   seq[string]
    score*:       int    ## 0-25 contribution to total score

proc findYaraBin(): string =
  ## Locate the yara binary — checks PATH and common install locations.
  ## Returns full path if found, empty string otherwise.
  when defined(windows):
    let (output, code) = execCmdEx("where yara 2>nul")
    if code == 0: return output.strip()
    return ""
  else:
    # 1. Try PATH first
    let (output, code) = execCmdEx("which yara 2>/dev/null")
    if code == 0: return output.strip()
    # 2. Probe common install locations (covers Homebrew, system, apt)
    const candidates = [
      "/opt/homebrew/bin/yara",   # Apple Silicon Homebrew
      "/usr/local/bin/yara",      # Intel Homebrew / manual install
      "/usr/bin/yara",            # apt / system
      "/usr/local/sbin/yara",
    ]
    for c in candidates:
      let (_, rc) = execCmdEx("test -x \"" & c & "\"")
      if rc == 0: return c
    return ""

proc scanWithYara*(filePath: string, rulesPath: string): YaraResult =
  ## Scan file with YARA rules. Returns structured match results.
  ## Score: +15 for first rule match, +5 for each additional, capped at 25.
  result = YaraResult(matched: false, matchCount: 0, ruleNames: @[], score: 0)

  if not fileExists(filePath):
    echo "[!] YARA: Target file not found"
    return

  # Locate yara binary — checks PATH and common Homebrew/system dirs
  let yaraBin = findYaraBin()
  if yaraBin == "":
    echo "[!] YARA: yara binary not found — install with:"
    when defined(windows):
      echo "         choco install yara  OR  scoop install yara"
    else:
      echo "         brew install yara  (macOS)  |  apt install yara  (Linux)"
    return

  if not fileExists(rulesPath):
    echo "[!] YARA: Rules file not found at: " & rulesPath
    return

  # Cross-platform redirect
  const devNull = when defined(windows): " 2>nul" else: " 2>/dev/null"

  # Run YARA against the main rules file (use full path)
  let cmd = "\"" & yaraBin & "\" -r \"" & rulesPath & "\" \"" & filePath & "\"" & devNull
  let (output, _) = execCmdEx(cmd)

  # Scan additional .yar files in signatures/ subdirectory
  var sigOutput = ""
  let sigDir = rulesPath.parentDir() / "signatures"
  if dirExists(sigDir):
    for entry in walkDir(sigDir):
      if entry.path.endsWith(".yar") or entry.path.endsWith(".yara"):
        let (so, _) = execCmdEx("\"" & yaraBin & "\" \"" & entry.path & "\" \"" & filePath & "\"" & devNull)
        sigOutput.add(so)

  let combined = output & sigOutput

  if combined.strip().len == 0:
    return

  result.matched = true
  for line in combined.splitLines():
    let trimmed = line.strip()
    if trimmed.len == 0: continue
    # YARA output format: "RuleName /path/to/file"
    let parts = trimmed.split(" ")
    if parts.len >= 1:
      let ruleName = parts[0]
      if ruleName.len > 0 and ruleName notin result.ruleNames:
        result.ruleNames.add(ruleName)
        inc result.matchCount

  # Score: 15 pts for first match, +5 per additional match, max 25
  if result.matchCount >= 1:
    result.score = min(15 + (result.matchCount - 1) * 5, 25)