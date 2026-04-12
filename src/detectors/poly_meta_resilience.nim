## poly_meta_resilience.nim
## Evaluates the detection result against polymorphic and metamorphic resilience
## Maps directly to "Resilience to Polymorphism and Metamorphism" (Paper pages 5-6)

import strutils, strformat
import ../analyzer/structural

type
  RiskLevel* = enum
    riskHigh = "HIGH (Fragile detection)"
    riskMedium = "MEDIUM (Partial evasion possible)"
    riskLow = "LOW (Highly mutation-resistant)"

  PolyMetaReport* = object
    mutationResistantCount*: int
    mutationSensitiveCount*: int
    residualRiskLevel*:      RiskLevel
    invariantsSummary*:      seq[string]

proc evaluateMutationResilience*(res: DetectionResult): PolyMetaReport =
  var report = PolyMetaReport()

  # ─── Mutation Resistant Invariants (The "Unavoidable" artifacts) ───────
  # According to the paper, attackers cannot mutate these without breaking functionality.

  if res.nimMainHierarchy.score > 0:
    inc report.mutationResistantCount
    report.invariantsSummary.add("✅ NimMain Hierarchy: Cannot be reordered without breaking the CRT startup or RTL initialization.")

  if res.gcMarkerClustering.score > 0:
    inc report.mutationResistantCount
    report.invariantsSummary.add("✅ GC Marker Clustering: `nimRegisterGlobalMarker` density anchors the main module logic.")

  if res.orcTricolorMotif.score > 0:
    inc report.mutationResistantCount
    report.invariantsSummary.add("✅ ORC GC Motif: The trial deletion state machine is too complex to be rewritten by a mutation engine.")

  if res.foreignThreadGC.score > 0:
    inc report.mutationResistantCount
    report.invariantsSummary.add("✅ Foreign Thread GC: Must establish stack bounds in foreign threads (e.g. DLL injection). Cannot be skipped.")

  if res.arcHooks.score > 0:
    inc report.mutationResistantCount
    report.invariantsSummary.add("✅ ARC Hooks Motif: =copy and =destroy hooks are intrinsically injected by transpiler for memory safety.")


  # ─── Mutation Sensitive Invariants (Removable via compiler flags/obfuscation) ───
  
  if res.tmStrings.score > 0:
    inc report.mutationSensitiveCount
    report.invariantsSummary.add("⚠️ _TM Strings: Structural strings present, but could be stripped with `-d:strip` or string obfuscators.")

  if res.sysFatalRefs.score > 0:
    inc report.mutationSensitiveCount
    report.invariantsSummary.add("⚠️ sysFatal Safety: Present, but could be eliminated with `--panics:on` and `--opt:speed`.")

  if res.moduleEncoding.score > 0:
    inc report.mutationSensitiveCount
    report.invariantsSummary.add("⚠️ Module Encoding (@m_): Detectable, but may be disabled or stripped by advanced obfuscation tools.")


  # Calculate residual risk based on the structural foundation remaining
  if report.mutationResistantCount >= 3:
    report.residualRiskLevel = riskLow
  elif report.mutationResistantCount >= 1:
    report.residualRiskLevel = riskMedium
  else:
    report.residualRiskLevel = riskHigh

  if report.mutationResistantCount == 0 and report.mutationSensitiveCount == 0:
    report.invariantsSummary.add("No structural invariants detected. Not a Nim transpilation signature.")

  return report
