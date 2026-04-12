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

proc yaraAvailable(): bool =
  ## Check if the yara binary is on PATH (cross-platform)
  when defined(windows):
    let (_, code) = execCmdEx("where yara 2>nul")
    result = (code == 0)
  else:
    let (_, code) = execCmdEx("which yara 2>/dev/null")
    result = (code == 0)

proc scanWithYara*(filePath: string, rulesPath: string): YaraResult =
  ## Scan file with YARA rules. Returns structured match results.
  ## Score: +15 for first rule match, +5 for each additional, capped at 25.
  result = YaraResult(matched: false, matchCount: 0, ruleNames: @[], score: 0)

  if not fileExists(filePath):
    echo "[!] YARA: Target file not found"
    return

  # Verify YARA binary is available (cross-platform)
  if not yaraAvailable():
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

  # Run YARA against the main rules file
  let cmd = "yara -r \"" & rulesPath & "\" \"" & filePath & "\"" & devNull
  let (output, _) = execCmdEx(cmd)

  # Scan additional .yar files in signatures/ subdirectory
  var sigOutput = ""
  let sigDir = rulesPath.parentDir() / "signatures"
  if dirExists(sigDir):
    for entry in walkDir(sigDir):
      if entry.path.endsWith(".yar") or entry.path.endsWith(".yara"):
        let (so, _) = execCmdEx("yara \"" & entry.path & "\" \"" & filePath & "\"" & devNull)
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