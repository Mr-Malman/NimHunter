## nimhunter.nim
## NimHunter v2 — Transpilation Signature Detection Framework
## Main entry point and orchestration pipeline
##
## Usage:
##   ./nimhunter <file>              # Scan single file
##   ./nimhunter --json <file>       # JSON output
##   ./nimhunter --batch <dir>       # Scan directory
##   ./nimhunter --generate-trainer  # Print ML training script

import os, strformat, strutils, parseopt
import analyzer/[pe_parser, demangler, structural]
import detectors/[yara_engine, ml_engine, poly_meta_resilience, deep_engine]
import utils/reporter

const VERSION = "2.0.0"
const BANNER = """
  _   _ _           _   _             _
 | \ | (_)_ __ ___ | | | |_   _ _ __ | |_ ___ _ __
 |  \| | | '_ ` _ \| |_| | | | | '_ \| __/ _ \ '__|
 | |\  | | | | | | |  _  | |_| | | | | ||  __/ |
 |_| \_|_|_| |_| |_|_| |_|\__,_|_| |_|\__\___|_|

 v""" & VERSION & """  |  Transpilation Signature Detection Framework
 Thesis: "The Transpilation Signature" — AIFS, Amity University
 Platform: """ & hostOS & " (" & hostCPU & ")" & """
"""

type
  RunMode = enum
    modeSingle, modeBatch, modeTrainer

  CLIOptions = object
    mode:      RunMode
    jsonOut:   bool
    noColor:   bool
    deepMode:  bool    ## --deep: run GIN/BERT/ACD/LIME modules
    target:    string
    rulesPath: string

# ─── Core scan function ───────────────────────────────────────────────────────

proc scanFile(path: string, rulesPath: string, jsonOut: bool, deepMode: bool = false) =
  if not jsonOut:
    echo reporter.colorize("─────────────────────────────────────────────────────────", "36")
    echo &"  Analyzing: {path}"
    echo reporter.colorize("─────────────────────────────────────────────────────────", "36")

  # Step 1: PE Validation + Metadata
  let peInfo = analyzeBinary(path)
  if not peInfo.isPE:
    if not jsonOut:
      echo "[!] Skipped: Not a Windows PE binary"
    return

  # Step 2: Layer 1 — YARA Signature Scan
  let yaraRes = scanWithYara(path, rulesPath)

  # Step 3: Layer 2 — Structural Invariant Analysis
  let buffer    = cast[seq[byte]](readFile(path))
  let structRes = analyzeCallCascade(buffer, peInfo.entryPoint, peInfo)

  # Step 4: Layer 3 — ML Engine (heuristic or ONNX)
  let mlRes = runMLEngine(structRes, peInfo)

  # Step 4.5: Poly/Meta Resilience Eval
  let polyRes = evaluateMutationResilience(structRes)

  # Step 5: Forensic path extraction (attribution)
  let bufStr = cast[string](buffer)
  let forensic = extractForensicPaths(bufStr)

  # Step 7 (optional): Deep Analysis — CFG+GIN, BERT, ACD, LIME
  var deepRes = DeepResult(available: false)
  if deepMode:
    deepRes = runDeepAnalysis(path)

  # Step 6: Build and emit base report (deepScore feeds into verdict calculation)
  let report = buildReport(path, peInfo, yaraRes, structRes, mlRes, polyRes,
                           if deepMode: deepRes.deepScore else: 0)

  if jsonOut:
    var j = report.toJson()
    if deepMode and deepRes.available:
      # Append deep_analysis block to JSON output
      let deepJson = &",\"deep_analysis\":{{\"deep_score\":{deepRes.deepScore}," &
                    &"\"combined_total\":{deepRes.combinedTotal}," &
                    &"\"cfg_nodes\":{deepRes.cfgNodes}," &
                    &"\"cfg_edges\":{deepRes.cfgEdges}}}"
      j = j[0..^2] & deepJson & "}"
    echo j
  else:
    report.printReport()
    if deepMode:
      echo reporter.colorize("── LAYER 5: DEEP ANALYSIS (GIN/BERT/ACD/LIME) ──────────────────", "35")
      if deepRes.available:
        echo &"  CFG Nodes   : {deepRes.cfgNodes}"
        echo &"  CFG Edges   : {deepRes.cfgEdges}"
        for m in deepRes.modules:
          if m.maxScore > 0:
            echo &"  {m.name:<18}: {m.score}/{m.maxScore}" &
                 (if m.error != "": &"  [!] {m.error}" else: "")
          else:
            echo &"  {m.name:<18}: (explanatory)" &
                 (if m.error != "": &"  [!] {m.error}" else: "")
        echo &"  DEEP SCORE  : {deepRes.deepScore}/30"
        echo &"  COMBINED    : {deepRes.combinedTotal}/100"
        if deepRes.cfgDotFile != "":
          echo &"  CFG graph   → {deepRes.cfgDotFile}"
        if deepRes.limeImageFile != "":
          echo &"  LIME chart  → {deepRes.limeImageFile}"
        for f in deepRes.allFindings:
          echo &"  {f}"
      else:
        echo "  Deep analysis unavailable — run: .venv/bin/python3.13 scripts/deep_analysis.py"
        for f in deepRes.allFindings:
          echo &"  {f}"
      echo ""
    if forensic.developerPaths.len > 0:
      echo "── FORENSIC PATH LEAKS (attribution) ──────────────────────"
      for p in forensic.developerPaths:
        echo &"  {p}"
      echo ""
    if forensic.packageNames.len > 0:
      echo "── THIRD-PARTY PACKAGES ────────────────────────────────────"
      for p in forensic.packageNames:
        echo &"  {p}"
      echo ""
    if forensic.nimVersion != "":
      echo &"  Nim version hint: {forensic.nimVersion}"
      echo ""

# ─── Batch scan ──────────────────────────────────────────────────────────────

proc scanBatch(dirPath: string, rulesPath: string, jsonOut: bool, deepMode: bool = false) =
  if not jsonOut:
    echo &"[*] Batch scanning: {dirPath}"
  var total = 0
  var hits  = 0
  for filePath in walkDirRec(dirPath):
    inc total
    let quick = analyzeBinary(filePath)
    if quick.isPE:
      scanFile(filePath, rulesPath, jsonOut, deepMode)
      inc hits
  if not jsonOut:
    echo &"[*] Scan complete: {hits}/{total} PE files analyzed"

# ─── CLI parser ──────────────────────────────────────────────────────────────

proc parseCLI(): CLIOptions =
  result = CLIOptions(
    mode:      modeSingle,
    jsonOut:   false,
    deepMode:  false,
    target:    "",
    rulesPath: "rules/main.yar"
  )

  var p = initOptParser()
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key
      of "json", "j":
        result.jsonOut = true
        # support --json <file>
        if p.val != "": result.target = p.val
      of "batch", "b":
        result.mode = modeBatch
        if p.val != "":
          result.target = p.val   # --batch=<dir>
        else:
          p.next()
          if p.kind == cmdArgument: result.target = p.val
      of "rules", "r":
        if p.val != "":
          result.rulesPath = p.val  # --rules=<path>
        else:
          p.next()
          if p.kind == cmdArgument: result.rulesPath = p.val
      of "generate-trainer":
        result.mode = modeTrainer
      of "deep", "d":
        result.deepMode = true
      of "no-color":
        result.noColor = true
      of "version", "v":
        echo "NimHunter v" & VERSION
        quit(0)
      of "help", "h":
        echo BANNER
        echo "Usage:"
        echo "  nimhunter <file>                  Scan a single PE file"
        echo "  nimhunter --json <file>            Output JSON report"
        echo "  nimhunter --batch <dir>            Scan all PE files in directory"
        echo "  nimhunter --rules <path> <file>    Use custom YARA rules path"
        echo "  nimhunter --deep <file>            Enable deep analysis (GIN/BERT/ACD/LIME)"
        echo "  nimhunter --no-color <file>        Disable ANSI color output"
        echo "  nimhunter --generate-trainer       Print ML model training script"
        echo "  nimhunter --version                Show version"
        quit(0)
      else: discard
    of cmdArgument:
      if result.target == "": result.target = p.key

# ─── Main ────────────────────────────────────────────────────────────────────

when isMainModule:
  let opts = parseCLI()

  if opts.noColor:
    reporter.useColors = false

  case opts.mode
  of modeTrainer:
    echo TRAINER_SCRIPT
    quit(0)

  of modeBatch:
    if opts.target == "":
      echo "[!] Error: --batch requires a directory path"
      quit(1)
    if not dirExists(opts.target):
      echo &"[!] Error: Directory not found: {opts.target}"
      quit(1)
    if not opts.jsonOut:
      echo BANNER
    scanBatch(opts.target, opts.rulesPath, opts.jsonOut, opts.deepMode)

  of modeSingle:
    if opts.target == "":
      echo BANNER
      echo "Usage: nimhunter <file_to_scan>"
      echo "       nimhunter --help for all options"
      quit(1)
    if not fileExists(opts.target):
      echo &"[!] Error: File not found: {opts.target}"
      quit(1)
    if not opts.jsonOut:
      echo BANNER
    scanFile(opts.target, opts.rulesPath, opts.jsonOut, opts.deepMode)