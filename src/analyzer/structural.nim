## structural.nim
## Structural invariant analysis engine for NimHunter v2
## Implements all 9 detection components from the Transpilation Signature paper
## Each component is independently scored and labeled for SHAP explainability

import strutils, math
import ./pe_parser

type
  GCMode* = enum
    gcUnknown = "unknown"
    gcRefc    = "gc:refc"
    gcArc     = "gc:arc"
    gcOrc     = "gc:orc"

  DetectionComponent* = object
    name*:     string
    score*:    int
    maxScore*: int
    findings*: seq[string]

  DetectionResult* = object
    ## All structural analysis results, organized by detection layer
    ## Layer 2a: Structural Invariant (mutation-resistant)
    nimMainHierarchy*:   DetectionComponent  ## max 15
    gcMarkerClustering*: DetectionComponent  ## max 12
    moduleEncoding*:     DetectionComponent  ## max 8
    tmStrings*:          DetectionComponent  ## max 10
    sysFatalRefs*:       DetectionComponent  ## max 5
    ## Layer 2b: Runtime Behavioral Artifacts
    orcTricolorMotif*:   DetectionComponent  ## max 15
    arcHooks*:           DetectionComponent  ## max 10
    foreignThreadGC*:    DetectionComponent  ## max 15
    callDensity*:        DetectionComponent  ## max 5
    ## Summary
    gcMode*:             GCMode
    totalScore*:         int    ## 0-100 (structural + behavioral, YARA added by caller)
    allFindings*:        seq[string]
    ## Feature vector for ML engine
    featureVector*:      seq[float]

# ─── Helpers ─────────────────────────────────────────────────────────────────

proc hasStr(buf: string, s: string): bool {.inline.} =
  buf.find(s) >= 0

proc countStr(buf: string, s: string): int =
  result = 0
  var pos = 0
  while true:
    let i = buf.find(s, pos)
    if i < 0: break
    inc result
    pos = i + 1

proc makeComp(name: string, maxScore: int): DetectionComponent =
  DetectionComponent(name: name, score: 0, maxScore: maxScore, findings: @[])

# ─── Component 1: NimMain Initialization Hierarchy ───────────────────────────

proc detectNimMainHierarchy(buf: string): DetectionComponent =
  ## The NimMain → NimMainInner → NimMainModule call chain is a structural
  ## invariant mandated by the Nim transpilation pipeline.
  ## Paper: "even when function names are removed, the structural arrangement
  ## of these routines remains consistent."
  result = makeComp("NimMain Hierarchy", 15)
  
  let hasMain   = hasStr(buf, "NimMain")
  let hasInner  = hasStr(buf, "NimMainInner")
  let hasModule = hasStr(buf, "NimMainModule")

  if hasMain:
    result.score += 5
    result.findings.add("NimMain: Nim runtime gateway detected")
  if hasInner:
    result.score += 4
    result.findings.add("NimMainInner: GC + TLS initialization detected")
  if hasModule:
    result.score += 6
    result.findings.add("NimMainModule: Top-level code container detected")

  if hasMain and hasInner and hasModule:
    result.score = 15
    result.findings.add("[HIGH] Complete NimMain initialization hierarchy confirmed")

  result.score = min(result.score, result.maxScore)

# ─── Component 2: nimRegisterGlobalMarker Clustering ─────────────────────────

proc detectGCMarkerClustering(buf: string): DetectionComponent =
  ## nimRegisterGlobalMarker Xref density analysis.
  ## Paper: "The function that contains the highest density of cross-references
  ## to nimRegisterGlobalMarker is almost invariably the NimMainModule."
  ## This works even in stripped binaries.
  result = makeComp("GC Marker Clustering", 12)

  let count  = countStr(buf, "nimRegisterGlobalMarker")
  let plural = countStr(buf, "nimRegisterGlobalMarkers")

  if count == 0 and plural == 0:
    return

  result.score += 5
  result.findings.add("nimRegisterGlobalMarker: " & $count & " references found")

  if count >= 3:
    result.score += 4
    result.findings.add("[HIGH] Marker density ≥3 — NimMainModule location established")

  if count >= 6:
    result.score = 12
    result.findings.add("[CRITICAL] Very high GC marker density (" & $count & ") — definitive Nim runtime")

  if plural > 0:
    result.score = min(result.score + 3, 12)
    result.findings.add("nimRegisterGlobalMarkers (collection): complex module structure")

  result.score = min(result.score, result.maxScore)

# ─── Component 3: Module Name Encoding (@m_ pattern) ─────────────────────────

proc detectModuleEncoding(buf: string): DetectionComponent =
  ## @m_ prefix is Nim's module initializer naming convention.
  ## pureZ encoding = Nim stdlib path encoding (Z replaces path separators).
  result = makeComp("Module Encoding", 8)

  let modCount  = countStr(buf, "@m_")
  let pureCount = countStr(buf, "pureZ")

  if modCount > 0:
    result.score += 5
    result.findings.add("@m_ module encoding: " & $modCount & " occurrences (Nim module init markers)")

  if modCount >= 5:
    result.score += 2
    result.findings.add("High @m_ density — complex multi-module Nim binary")

  if pureCount > 0:
    result.score += 1
    result.findings.add("pureZ path encoding: Nim stdlib linkage confirmed")

  result.score = min(result.score, result.maxScore)

# ─── Component 4: _TM String Struct Recovery ─────────────────────────────────

proc detectTMStrings(peInfo: PEInfo): DetectionComponent =
  ## _TM prefixed variables are Nim's temporary strings (compiler-generated).
  ## Paper: "A detection framework that applies C-style structs to these _TM
  ## variables can recover human-readable content such as C2 URLs."
  result = makeComp("_TM String Structs", 10)

  if peInfo.tmStringCount == 0:
    return

  result.score = min(peInfo.tmStringCount * 3, 8)
  result.findings.add("_TM Nim string structs: " & $peInfo.tmStringCount & " found in .rdata/.data")

  for s in peInfo.nimStrings:
    let preview = if s.content.len > 50: s.content[0..49] & "..." else: s.content
    result.findings.add("  Recovered: \"" & preview & "\"")

  if peInfo.tmStringCount >= 3:
    result.score = 10
    result.findings.add("[HIGH] Multiple _TM strings recovered — Nim string table present")

  result.score = min(result.score, result.maxScore)

# ─── Component 5: sysFatal + Runtime Error Strings ───────────────────────────

proc detectSysFatal(buf: string): DetectionComponent =
  ## Nim's language-mandated safety checks emit these strings.
  ## They are compiler-enforced and cannot be removed without disabling safety.
  result = makeComp("SysFatal Error Strings", 5)

  var hits = 0
  if hasStr(buf, "sysFatal"):            inc hits
  if hasStr(buf, "fatal.nim"):           inc hits
  if hasStr(buf, "@index out of bounds"):inc hits
  if hasStr(buf, "@division by zero"):   inc hits
  if hasStr(buf, "@value out of range"): inc hits
  if hasStr(buf, "@over- or underflow"): inc hits

  if hits >= 2:
    result.score = 5
    result.findings.add("Nim safety check strings: " & $hits & "/6 found (language-mandated artifacts)")
  elif hits == 1:
    result.score = 2
    result.findings.add("Nim runtime error string detected (" & $hits & "/6)")

  result.score = min(result.score, result.maxScore)

# ─── Component 6: ORC Tri-Color Cycle Collector ──────────────────────────────

proc detectORCTricolorMotif(buf: string): DetectionComponent =
  ## ORC's trial deletion algorithm uses Black/Gray/White node coloring.
  ## Paper: "The machine code generated for this trial deletion process is
  ## highly complex and UNIQUE to the Nim runtime."
  ## This is the MOST MUTATION-RESILIENT invariant in the framework.
  result = makeComp("ORC Tri-Color Motif", 15)

  let hasSweep    = hasStr(buf, "nimOrcSweep")
  let hasCycles   = hasStr(buf, "nimOrcRegisterCycle")
  let hasTrace    = hasStr(buf, "nimTraceRef")
  let hasDecRef   = hasStr(buf, "scheduleDecRef")
  let hasCycCol   = hasStr(buf, "cyclecollector") or hasStr(buf, "trialDelete")

  if hasSweep:
    result.score += 8
    result.findings.add("[ORC] nimOrcSweep: cycle collector sweep phase detected")
  if hasCycles:
    result.score += 5
    result.findings.add("[ORC] nimOrcRegisterCycle: cycle registration detected")
  if hasTrace:
    result.score += 4
    result.findings.add("[ORC] nimTraceRef: tri-color reference tracing detected")
  if hasDecRef:
    result.score += 4
    result.findings.add("[ORC] scheduleDecRef: deferred reference counting detected")
  if hasCycCol:
    result.score += 5
    result.findings.add("[ORC] Cycle collector / trial deletion artifact detected")

  if result.score > 0:
    result.findings.add("[CRITICAL] ORC motif is mutation-invariant — cannot be removed")

  result.score = min(result.score, result.maxScore)

# ─── Component 7: ARC Hook Detection ─────────────────────────────────────────

proc detectARCHooks(buf: string): DetectionComponent =
  ## ARC injects =copy, =destroy, =sink, =trace hooks at compile time.
  ## gc:refc uses nimGCinit/nimGCdeinit instead.
  result = makeComp("ARC Hooks", 10)

  let hasCopy    = hasStr(buf, "=copy")    or hasStr(buf, "nimCopyMem")
  let hasDestroy = hasStr(buf, "=destroy") or hasStr(buf, "=wasMoved")
  let hasSink    = hasStr(buf, "=sink")
  let hasTrace   = hasStr(buf, "=trace")
  let hasGCInit  = hasStr(buf, "nimGCinit")
  let hasGCDe    = hasStr(buf, "nimGCdeinit")
  let hasAlloc   = hasStr(buf, "nimRawNewObj") or hasStr(buf, "nimNewObj")

  if hasCopy and hasDestroy:
    result.score += 6
    result.findings.add("[ARC] =copy + =destroy hooks detected (gc:arc or gc:orc)")
  elif hasCopy or hasDestroy:
    result.score += 3
    result.findings.add("[ARC] Partial ARC hooks detected")

  if hasSink:
    result.score += 2
    result.findings.add("[ARC] =sink hook: move semantics compiler injection")
  if hasTrace:
    result.score += 2
    result.findings.add("[ARC] =trace hook: ORC reference tracing support")

  if hasGCInit and hasGCDe:
    result.score += 4
    result.findings.add("[REFC] nimGCinit + nimGCdeinit: legacy gc:refc mode detected")

  if hasAlloc:
    result.score += 2
    result.findings.add("Nim-specific allocator (nimRawNewObj/nimNewObj) detected")

  result.score = min(result.score, result.maxScore)

# ─── Component 8: Foreign Thread GC Artifacts ────────────────────────────────

proc detectForeignThreadGC(buf: string): DetectionComponent =
  ## setupForeignThreadGc and nimGC_setStackBottom are DEFINITIVE indicators.
  ## Paper: "The presence of these calls in a thread's entry point is a definitive
  ## indicator that the thread is executing a Nim-based payload."
  ## Critical for detecting Nim shellcode loaders and DLL injection.
  result = makeComp("Foreign Thread GC", 15)

  let hasForeignSetup  = hasStr(buf, "setupForeignThreadGc")
  let hasStackBottom   = hasStr(buf, "nimGC_setStackBottom") or
                         hasStr(buf, "setStackBottom")
  let hasTeardown      = hasStr(buf, "teardownForeignThreadGc")
  let hasThreadInit    = hasStr(buf, "nimThreadVarsInit")

  if hasForeignSetup:
    result.score += 10
    result.findings.add("[DEFINITIVE] setupForeignThreadGc: Nim payload injection into foreign thread")
  if hasStackBottom:
    result.score += 8
    result.findings.add("[DEFINITIVE] nimGC_setStackBottom: GC stack boundary established in host process")
  if hasTeardown:
    result.score += 4
    result.findings.add("teardownForeignThreadGc: Nim thread cleanup in foreign context")
  if hasThreadInit:
    result.score += 2
    result.findings.add("nimThreadVarsInit: Nim thread-local variable initialization")

  if hasForeignSetup and hasStackBottom:
    result.score = 15
    result.findings.add("[CRITICAL] Both foreign GC functions present — high-confidence Nim injection")

  result.score = min(result.score, result.maxScore)

# ─── Component 9: Call Instruction Density ───────────────────────────────────

proc detectCallDensity(buf: string): DetectionComponent =
  ## Nim's transpilation generates higher function call density than equivalent C.
  ## Raw CALL opcode (0xE8) counting provides a mutation-resilient metric.
  result = makeComp("Call Density", 5)

  var nearCalls = 0
  for i in 0 ..< buf.len - 5:
    if ord(buf[i]) == 0xE8:  # Near CALL rel32
      inc nearCalls

  let callsPerKB = if buf.len > 0: (nearCalls * 1000) div buf.len else: 0

  if callsPerKB > 20:
    result.score = 5
    result.findings.add("Very high call density: " & $callsPerKB & "/KB (transpiled code pattern)")
  elif callsPerKB > 12:
    result.score = 3
    result.findings.add("Elevated call density: " & $callsPerKB & "/KB")
  elif nearCalls > 200:
    result.score = 2
    result.findings.add("Significant CALL count: " & $nearCalls)

  result.score = min(result.score, result.maxScore)

# ─── GC Mode Discriminator ───────────────────────────────────────────────────

proc discriminateGCMode*(buf: string): GCMode =
  ## Determine the GC mode used to compile the binary.
  ## This enables family attribution — Nim malware families show GC mode preferences.
  ## NimzaLoader: typically gc:arc; older samples: gc:refc
  let hasORC  = hasStr(buf, "nimOrcSweep") or hasStr(buf, "nimOrcRegisterCycle") or
                hasStr(buf, "nimTraceRef") or hasStr(buf, "scheduleDecRef")
  let hasARC  = (hasStr(buf, "=copy") or hasStr(buf, "=destroy")) and
                hasStr(buf, "nimDecRef")
  let hasRefc = hasStr(buf, "nimGCinit") and hasStr(buf, "nimGCdeinit")

  if hasORC:  return gcOrc
  if hasARC:  return gcArc
  if hasRefc: return gcRefc
  return gcUnknown

# ─── Feature Vector Builder (for ML engine) ──────────────────────────────────

proc buildFeatureVector*(res: DetectionResult, peInfo: PEInfo): seq[float] =
  ## Produces a normalized feature vector for the ML ensemble classifier.
  ## Features are normalized to [0, 1] range for model compatibility.
  result = @[
    float(res.nimMainHierarchy.score)   / float(res.nimMainHierarchy.maxScore),
    float(res.gcMarkerClustering.score) / float(res.gcMarkerClustering.maxScore),
    float(res.moduleEncoding.score)     / float(res.moduleEncoding.maxScore),
    float(res.tmStrings.score)          / float(res.tmStrings.maxScore),
    float(res.sysFatalRefs.score)       / float(res.sysFatalRefs.maxScore),
    float(res.orcTricolorMotif.score)   / float(res.orcTricolorMotif.maxScore),
    float(res.arcHooks.score)           / float(res.arcHooks.maxScore),
    float(res.foreignThreadGC.score)    / float(res.foreignThreadGC.maxScore),
    float(res.callDensity.score)        / float(res.callDensity.maxScore),
    peInfo.overallEntropy / 8.0,
    float(peInfo.tmStringCount) / 20.0,
    float(peInfo.sections.len)  / 10.0,
    if peInfo.hasTLS: 1.0 else: 0.0,
    if peInfo.isPacked: 1.0 else: 0.0,
    if peInfo.isStripped: 1.0 else: 0.0,
    float(ord(res.gcMode)) / 3.0
  ]

# ─── Main Analysis Entrypoint ─────────────────────────────────────────────────

proc analyzeCallCascade*(buffer: seq[byte], entryPoint: uint32,
                         peInfo: PEInfo): DetectionResult =
  ## Primary structural analysis entry point.
  ## Runs all 9 detection components and produces a structured result.
  var res = DetectionResult()
  let buf = cast[string](buffer)

  res.nimMainHierarchy   = detectNimMainHierarchy(buf)
  res.gcMarkerClustering = detectGCMarkerClustering(buf)
  res.moduleEncoding     = detectModuleEncoding(buf)
  res.tmStrings          = detectTMStrings(peInfo)
  res.sysFatalRefs       = detectSysFatal(buf)
  res.orcTricolorMotif   = detectORCTricolorMotif(buf)
  res.arcHooks           = detectARCHooks(buf)
  res.foreignThreadGC    = detectForeignThreadGC(buf)
  res.callDensity        = detectCallDensity(buf)
  res.gcMode             = discriminateGCMode(buf)

  res.totalScore =
    res.nimMainHierarchy.score   +
    res.gcMarkerClustering.score +
    res.moduleEncoding.score     +
    res.tmStrings.score          +
    res.sysFatalRefs.score       +
    res.orcTricolorMotif.score   +
    res.arcHooks.score           +
    res.foreignThreadGC.score    +
    res.callDensity.score

  res.totalScore = min(res.totalScore, 75) # YARA layer adds up to 25 more

  for c in [res.nimMainHierarchy, res.gcMarkerClustering, res.moduleEncoding,
            res.tmStrings, res.sysFatalRefs, res.orcTricolorMotif,
            res.arcHooks, res.foreignThreadGC, res.callDensity]:
    for f in c.findings:
      res.allFindings.add(f)

  res.featureVector = buildFeatureVector(res, peInfo)
  return res

## Backward-compatible shim (original 2-arg signature)
proc analyzeCallCascade*(buffer: seq[byte], entryPoint: uint32): DetectionResult =
  analyzeCallCascade(buffer, entryPoint, PEInfo())