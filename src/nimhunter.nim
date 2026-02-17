import os, strformat, sugar
import analyzer/[pe_parser, demangler, structural]
import detectors/yara_engine

proc runHunt(target: string) =
  echo "---------------------------------------------------"
  echo &"[*] ANALYZING: {target}"
  echo "---------------------------------------------------"

  # 1. PE Check
  let peInfo = analyzeBinary(target)
  if not peInfo.isPE:
    echo "[!] Skip: Not a Windows PE file."
    return

  # 2. Layer 1: YARA Signature Scan
  let yaraMatch = scanWithYara(target, "rules/main.yar")
  
  # 3. Layer 2: Structural Analysis
  # Read file into buffer for Capstone
  let buffer = cast[seq[byte]](readFile(target))
  let structRes = analyzeCallCascade(buffer, peInfo.entryPoint)

  # 4. Final Aggregation
  var finalScore = if yaraMatch: 60 else: 0
  finalScore += structRes.score

  echo &"\n[+] ANALYSIS COMPLETE"
  echo &"    - Architecture: {peInfo.arch}"
  echo &"    - Detection Score: {finalScore}/100"
  
  for finding in structRes.findings:
    echo &"    - [Heuristic] {finding}"

  if finalScore >= 70:
    echo "\n[!!!] VERDICT: HIGH CONFIDENCE NIM MALWARE"
  elif finalScore >= 40:
    echo "\n[?] VERDICT: SUSPICIOUS NIM ARTIFACTS DETECTED"
  else:
    echo "\n[✓] VERDICT: CLEAN OR NON-NIM BINARY"

when isMainModule:
  if paramCount() < 1:
    echo "Usage: ./nimhunter <file_to_scan>"
  else:
    runHunt(paramStr(1))