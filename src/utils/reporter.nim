## reporter.nim
## Structured output generator for NimHunter v2
## Supports plain text console output and machine-readable JSON

import strutils, strformat, times, sequtils
import ../analyzer/pe_parser
import ../analyzer/structural
import ../detectors/yara_engine
import ../detectors/ml_engine
import ../detectors/poly_meta_resilience

var useColors* = true

proc colorize*(text, code: string): string =
  if useColors: "\e[" & code & "m" & text & "\e[0m"
  else: text

const
  cRed*    = "31"
  cGreen*  = "32"
  cYellow* = "33"
  cCyan*   = "36"
  cBold*   = "1"

type
  VerdictLevel* = enum
    verdictClean      = "CLEAN OR NON-NIM BINARY"
    verdictSuspicious = "SUSPICIOUS NIM ARTIFACTS DETECTED"
    verdictHigh       = "HIGH CONFIDENCE NIM MALWARE"
    verdictDefinitive = "DEFINITIVE NIM MALWARE"

  FullReport* = object
    filePath*:     string
    timestamp*:    string
    peInfo*:       PEInfo
    yaraResult*:   YaraResult
    structResult*: DetectionResult
    polyReport*:   PolyMetaReport
    mlResult*:     MLResult
    totalScore*:   int
    verdict*:      VerdictLevel

proc calcVerdict(score: int): VerdictLevel =
  if score >= 90:  verdictDefinitive
  elif score >= 70: verdictHigh
  elif score >= 40: verdictSuspicious
  else:             verdictClean

proc buildReport*(filePath: string, peInfo: PEInfo, yaraResult: YaraResult,
                  structResult: DetectionResult, mlResult: MLResult, polyReport: PolyMetaReport): FullReport =
  let totalScore = min(yaraResult.score + structResult.totalScore + mlResult.score, 100)
  FullReport(
    filePath:     filePath,
    timestamp:    now().format("yyyy-MM-dd HH:mm:ss"),
    peInfo:       peInfo,
    yaraResult:   yaraResult,
    structResult: structResult,
    polyReport:   polyReport,
    mlResult:     mlResult,
    totalScore:   totalScore,
    verdict:      calcVerdict(totalScore)
  )

# ─── Plain text report ────────────────────────────────────────────────────────

proc printReport*(r: FullReport) =
  echo ""
  echo colorize("═══════════════════════════════════════════════════════════", cCyan)
  echo colorize("  NimHunter v2 — Analysis Report", cBold)
  echo &"  File:      {r.filePath}"
  echo &"  Time:      {r.timestamp}"
  echo colorize("═══════════════════════════════════════════════════════════", cCyan)
  echo ""
  echo "── PE METADATA ─────────────────────────────────────────────"
  echo &"  Architecture : {r.peInfo.arch}"
  echo &"  Entry Point  : 0x{r.peInfo.entryPoint:08X}"
  echo &"  GC Mode      : {$r.structResult.gcMode}"
  echo &"  Stripped     : {r.peInfo.isStripped}"
  echo &"  Packed       : {r.peInfo.isPacked}"
  echo &"  Has TLS      : {r.peInfo.hasTLS}"
  echo &"  Entropy      : {r.peInfo.overallEntropy:.2f}/8.0"
  echo ""

  if r.peInfo.sections.len > 0:
    echo "── SECTIONS ────────────────────────────────────────────────"
    for s in r.peInfo.sections:
      let exec = if s.isExecutable: "X" else: "-"
      let wr   = if s.isWritable:   "W" else: "-"
      echo &"  {s.name:<10} VA=0x{s.virtualAddress:08X}  Entropy={s.entropy:.2f}  [{exec}{wr}]"
    echo ""

  if r.peInfo.importedDLLs.len > 0:
    echo "── IMPORTED DLLs ───────────────────────────────────────────"
    for dll in r.peInfo.importedDLLs:
      echo &"  {dll}"
    echo ""

  echo "── LAYER 1: YARA SIGNATURE ─────────────────────────────────"
  if r.yaraResult.matched:
    echo &"  Rules matched : {r.yaraResult.matchCount}"
    for rule in r.yaraResult.ruleNames:
      echo &"  [+] {rule}"
    echo &"  Score contribution: +{r.yaraResult.score}/25"
  else:
    echo "  No YARA matches  (score: +0/25)"
  echo ""

  echo colorize("── LAYER 2: STRUCTURAL INVARIANTS ──────────────────────────", cCyan)
  for comp in [r.structResult.nimMainHierarchy,
               r.structResult.gcMarkerClustering,
               r.structResult.moduleEncoding,
               r.structResult.tmStrings,
               r.structResult.sysFatalRefs,
               r.structResult.orcTricolorMotif,
               r.structResult.arcHooks,
               r.structResult.foreignThreadGC,
               r.structResult.callDensity,
               r.structResult.offensiveLibs]:
    if comp.score > 0:
      echo &"  [{comp.score:2}/{comp.maxScore}] {comp.name}"
      for f in comp.findings:
        if f.startsWith("[HIGH]"):
          echo colorize("         → " & f, cRed)
        elif f.contains("Offensive library"):
          echo colorize("         → " & f, cYellow)
        else:
          echo &"         → {f}"
  echo &"  Structural score: +{r.structResult.totalScore}/75"
  echo ""

  echo colorize("── LAYER 3: POLY/META RESILIENCE ───────────────────────────", cCyan)
  let riskColor = if r.polyReport.residualRiskLevel == riskHigh: cRed elif r.polyReport.residualRiskLevel == riskMedium: cYellow else: cGreen
  echo &"  Resistant Invariants : {r.polyReport.mutationResistantCount}"
  echo &"  Sensitive Invariants : {r.polyReport.mutationSensitiveCount}"
  echo &"  Evasion Risk Level   : {colorize($r.polyReport.residualRiskLevel, riskColor)}"
  if r.polyReport.invariantsSummary.len > 0:
    for s in r.polyReport.invariantsSummary:
      echo &"    {s}"
  echo ""

  echo colorize("── LAYER 4: ML ENGINE ──────────────────────────────────────", cCyan)
  echo &"  Model loaded : {r.mlResult.modelAvailable}"
  echo &"  Confidence   : {r.mlResult.confidence:.3f}"
  echo &"  Score        : +{r.mlResult.score}/10"
  if r.mlResult.topFeatures.len > 0:
    echo "  Top features :"
    for f in r.mlResult.topFeatures[0..min(4, r.mlResult.topFeatures.len-1)]:
      echo &"    {f.name:<25} = {f.value:.3f}"
  echo ""

  if r.peInfo.nimStrings.len > 0:
    echo "── RECOVERED NIM STRINGS ───────────────────────────────────"
    for s in r.peInfo.nimStrings[0..min(9, r.peInfo.nimStrings.len-1)]:
      echo &"  0x{s.offset:08X}: {s.content}"
    echo ""

  let maxBar = 20
  let filled = int(float(r.totalScore) / 100.0 * float(maxBar))
  var bar = "["
  for i in 1..maxBar:
    if i <= filled: bar &= "█"
    else: bar &= "░"
  bar &= "]"

  echo colorize("═══════════════════════════════════════════════════════════", cCyan)
  echo &"  TOTAL SCORE : {r.totalScore}/100    " & colorize(bar, if r.totalScore >= 70: cRed elif r.totalScore >= 40: cYellow else: cGreen)
  case r.verdict
  of verdictClean:
    echo colorize("  VERDICT     : [✓] CLEAN OR NON-NIM BINARY", cGreen)
  of verdictSuspicious:
    echo colorize("  VERDICT     : [?] SUSPICIOUS NIM ARTIFACTS DETECTED", cYellow)
  of verdictHigh:
    echo colorize("  VERDICT     : [!!!] HIGH CONFIDENCE NIM MALWARE", cRed)
  of verdictDefinitive:
    echo colorize("  VERDICT     : [!!!] DEFINITIVE NIM MALWARE — STRUCTURAL INVARIANTS CONFIRMED", cRed & ";" & cBold)
  echo colorize("═══════════════════════════════════════════════════════════", cCyan)
  echo ""

# ─── JSON report ─────────────────────────────────────────────────────────────

proc escapeJson(s: string): string =
  result = s.replace("\\", "\\\\").replace("\"", "\\\"")
               .replace("\n", "\\n").replace("\r", "\\r")

proc toJson*(r: FullReport): string =
  var j = "{\n"
  j &= &"  \"file\": \"{escapeJson(r.filePath)}\",\n"
  j &= &"  \"timestamp\": \"{r.timestamp}\",\n"
  j &= &"  \"verdict\": \"{$r.verdict}\",\n"
  j &= &"  \"total_score\": {r.totalScore},\n"
  j &= &"  \"gc_mode\": \"{$r.structResult.gcMode}\",\n"

  j &= "  \"pe_metadata\": {\n"
  j &= &"    \"arch\": \"{r.peInfo.arch}\",\n"
  j &= &"    \"entry_point\": \"0x{r.peInfo.entryPoint:08X}\",\n"
  j &= &"    \"entropy\": {r.peInfo.overallEntropy:.3f},\n"
  j &= &"    \"stripped\": {r.peInfo.isStripped},\n"
  j &= &"    \"packed\": {r.peInfo.isPacked},\n"
  j &= &"    \"has_tls\": {r.peInfo.hasTLS},\n"
  j &= &"    \"tm_string_count\": {r.peInfo.tmStringCount},\n"
  j &= "    \"imported_dlls\": ["
  j &= r.peInfo.importedDLLs.mapIt("\"" & escapeJson(it) & "\"").join(", ")
  j &= "]\n"
  j &= "  },\n"

  j &= "  \"component_scores\": {\n"
  j &= &"    \"yara_layer\": {{\"score\": {r.yaraResult.score}, \"matches\": {r.yaraResult.matchCount}}},\n"

  template compJson(comp: DetectionComponent): string =
    "{\"score\": " & $comp.score & ", \"max\": " & $comp.maxScore & "}"

  j &= "    \"structural_layer\": {\n"
  j &= &"      \"nim_main_hierarchy\": {compJson(r.structResult.nimMainHierarchy)},\n"
  j &= &"      \"gc_marker_clustering\": {compJson(r.structResult.gcMarkerClustering)},\n"
  j &= &"      \"module_encoding\": {compJson(r.structResult.moduleEncoding)},\n"
  j &= &"      \"tm_strings\": {compJson(r.structResult.tmStrings)},\n"
  j &= &"      \"sys_fatal\": {compJson(r.structResult.sysFatalRefs)},\n"
  j &= &"      \"orc_tricolor\": {compJson(r.structResult.orcTricolorMotif)},\n"
  j &= &"      \"arc_hooks\": {compJson(r.structResult.arcHooks)},\n"
  j &= &"      \"foreign_thread_gc\": {compJson(r.structResult.foreignThreadGC)},\n"
  j &= &"      \"call_density\": {compJson(r.structResult.callDensity)},\n"
  j &= &"      \"total\": {r.structResult.totalScore}\n"
  j &= "    },\n"
  j &= &"    \"ml_layer\": {{\"score\": {r.mlResult.score}, \"confidence\": {r.mlResult.confidence:.3f}}}\n"
  j &= "  },\n"

  # YARA rule names
  j &= "  \"yara_rules_matched\": ["
  j &= r.yaraResult.ruleNames.mapIt("\"" & escapeJson(it) & "\"").join(", ")
  j &= "],\n"

  # Feature vector
  j &= "  \"feature_vector\": ["
  j &= r.structResult.featureVector.mapIt($it).join(", ")
  j &= "],\n"

  # All findings
  j &= "  \"findings\": [\n"
  let findings = r.structResult.allFindings
  for i, f in findings:
    let comma = if i < findings.len - 1: "," else: ""
    j &= "    \"" & escapeJson(f) & "\"" & comma & "\n"
  j &= "  ]\n"
  j &= "}"
  return j