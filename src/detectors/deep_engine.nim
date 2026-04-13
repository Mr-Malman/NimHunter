## deep_engine.nim
## NimHunter v2 — Deep Analysis Engine
## Calls the Python deep_analysis.py subprocess and parses its JSON output.
## Activated by the --deep CLI flag.

import os, osproc, json, strformat, strutils, strtabs

type
  DeepModuleResult* = object
    name*:    string
    score*:   int
    maxScore*: int
    error*:   string
    findings*: seq[string]

  DeepResult* = object
    available*:    bool
    deepScore*:    int       ## 0-30 pts from all 4 deep modules
    combinedTotal*: int      ## normalized 0-100
    modules*:      seq[DeepModuleResult]
    allFindings*:  seq[string]
    cfgNodes*:     int
    cfgEdges*:     int
    cfgDotFile*:   string
    limeImageFile*: string
    bertScore*:    int
    acdScore*:     float

proc findPython(): string =
  ## Find the project venv Python interpreter (tries CWD-relative venv first).
  let candidates = [
    ".venv/bin/python3.13",
    getAppDir() / ".." / ".venv" / "bin" / "python3.13",
    "/opt/homebrew/bin/python3.13",
    "python3",
  ]
  for c in candidates:
    if fileExists(c): return c
  return "python3"

proc runDeepAnalysis*(pePath: string): DeepResult =
  result = DeepResult(available: false, deepScore: 0)

  let pythonBin = findPython()
  # Search for script relative to CWD first, then relative to binary location
  var script = "scripts/deep_analysis.py"
  if not fileExists(script):
    script = getAppDir() / ".." / "scripts" / "deep_analysis.py"
  if not fileExists(script):
    script = getAppDir() / "scripts" / "deep_analysis.py"

  if not fileExists(script):
    result.allFindings.add("[!] scripts/deep_analysis.py not found — run from project root")
    return

  let cmd = &"{pythonBin} {script} {pePath}"
  let (output, exitCode) = execCmdEx(cmd)

  if exitCode != 0 or output.strip() == "":
    result.allFindings.add("[!] Deep analysis subprocess failed")
    return

  # Parse JSON output from deep_analysis.py
  # It writes to stderr for progress and JSON to stdout
  # Find the JSON block
  var jsonStr = ""
  for line in output.splitLines():
    if line.startsWith("{") or jsonStr.len > 0:
      jsonStr.add(line & "\n")

  if jsonStr == "":
    result.allFindings.add("[!] No JSON output from deep_analysis.py")
    return

  try:
    let j = parseJson(jsonStr)

    result.available    = true
    result.deepScore    = j{"deep_score"}.getInt(0)
    result.combinedTotal = j{"combined_total"}.getInt(0)

    # Extract per-module results
    let layers = j{"layers"}
    if layers != nil:
      # CFG + GIN
      let gin = layers{"cfg_gin"}
      if gin != nil:
        result.cfgNodes   = gin{"node_count"}.getInt(0)
        result.cfgEdges   = gin{"edge_count"}.getInt(0)
        result.cfgDotFile = gin{"cfg_dot"}.getStr("")
        result.modules.add(DeepModuleResult(
          name:    "CFG+GIN",
          score:   gin{"gin_score"}.getInt(0),
          maxScore: 15,
          error:   gin{"error"}.getStr(""),
        ))

      # BERT Next-Byte
      let bert = layers{"bert_nextbyte"}
      if bert != nil:
        result.bertScore = bert{"nim_score"}.getInt(0)
        result.modules.add(DeepModuleResult(
          name:    "BERT Next-Byte",
          score:   result.bertScore,
          maxScore: 10,
          error:   bert{"error"}.getStr(""),
        ))

      # ACD
      let acd = layers{"acd_anomaly"}
      if acd != nil:
        result.acdScore = acd{"anomaly_score"}.getFloat(0.0)
        result.modules.add(DeepModuleResult(
          name:    "ACD Anomaly",
          score:   int(result.acdScore),
          maxScore: 5,
          error:   acd{"error"}.getStr(""),
        ))

      # LIME
      let lime = layers{"lime"}
      if lime != nil:
        result.limeImageFile = lime{"explanation_png"}.getStr("")
        result.modules.add(DeepModuleResult(
          name:    "LIME Explain",
          score:   0,   # LIME is explanatory, not scored
          maxScore: 0,
          error:   lime{"error"}.getStr(""),
        ))

    # Findings
    for f in j{"findings"}:
      result.allFindings.add(f.getStr())

  except JsonParsingError as e:
    result.allFindings.add(&"[!] JSON parse error: {e.msg}")
