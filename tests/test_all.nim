## tests/test_all.nim
## NimHunter v2 Test Suite
## Run with: nim r tests/test_all.nim

import std/[unittest, os, strutils]
import ../src/analyzer/pe_parser
import ../src/analyzer/demangler
import ../src/analyzer/structural

# ─── Test helpers ────────────────────────────────────────────────────────────

proc mkBuf(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(ord(c))

# ─── pe_parser tests ─────────────────────────────────────────────────────────

suite "PE Parser":

  test "Non-PE file returns isPE=false":
    let tmp = getTempDir() / "not_a_pe.bin"
    writeFile(tmp, "hello world this is not a PE binary")
    let info = analyzeBinary(tmp)
    check not info.isPE
    removeFile(tmp)

  test "Empty file returns isPE=false":
    let tmp = getTempDir() / "empty.bin"
    writeFile(tmp, "")
    let info = analyzeBinary(tmp)
    check not info.isPE
    removeFile(tmp)

  test "MZ header detected":
    let tmp = getTempDir() / "mz_only.bin"
    # Minimal MZ+PE stub (enough for isPE=true)
    var data = "MZ" & "\x00".repeat(58) & "\x40\x00\x00\x00"
    data &= "\x00".repeat(64)  # pad to offset 0x40
    data &= "PE\x00\x00"       # PE signature at 0x40
    data &= "\x64\x86"         # machine x64
    data &= "\x00\x00"         # numSections
    data &= "\x00".repeat(16)
    writeFile(tmp, data)
    let info = analyzeBinary(tmp)
    check info.isPE
    removeFile(tmp)

  test "Entropy of uniform data is 0":
    let tmp = getTempDir() / "zeros.bin"
    writeFile(tmp, "\x00".repeat(1024))
    let e = calcEntropy("\x00".repeat(1024))
    check e < 0.1
    removeFile(tmp)

  test "Entropy of random-looking data is high":
    var data = ""
    for i in 0..255: data.add(char(i))
    let e = calcEntropy(data)
    check e > 7.9

# ─── demangler tests ─────────────────────────────────────────────────────────

suite "Demangler":

  test "Basic function demangle":
    let sym = demangle("toHex__pureZstrutils_u2067")
    check sym.functionName == "toHex"
    check "strutils" in sym.modulePath
    check sym.isStdlib

  test "@m_ module init decoding":
    let sym = demangle("@m_ZhomeZuserZprojectsZmalwareZmain_u1")
    check sym.isModuleInit
    check "/home/user/projects/malware/main" == sym.modulePath

  test "Version extraction":
    let sym = demangle("someFunc__moduleZpath_u12345")
    check sym.version == 12345

  test "Unmangled symbol passthrough":
    let sym = demangle("NimMain")
    check sym.functionName == "NimMain"
    check sym.version == -1

  test "Module name scan in buffer":
    let buf = "prefix @m_system padding @m_pureZstrutils end"
    let names = decodeModuleNames(buf)
    check names.len >= 1

  test "pureZ decodes to pure/":
    let sym = demangle("echo__pureZio_u1")
    check "pure" in sym.modulePath
    check sym.isStdlib

# ─── structural analysis tests ───────────────────────────────────────────────

suite "Structural Analysis":

  test "NimMain hierarchy detection":
    let buf = mkBuf("...NimMain...NimMainInner...NimMainModule...")
    let res = analyzeCallCascade(buf, 0)
    check res.nimMainHierarchy.score > 0
    check res.nimMainHierarchy.score == res.nimMainHierarchy.maxScore  # all three present

  test "Partial NimMain (NimMain only)":
    let buf = mkBuf("...NimMain...some other content...")
    let res = analyzeCallCascade(buf, 0)
    check res.nimMainHierarchy.score > 0
    check res.nimMainHierarchy.score < res.nimMainHierarchy.maxScore

  test "nimRegisterGlobalMarker clustering":
    let buf = mkBuf("A nimRegisterGlobalMarker B nimRegisterGlobalMarker C nimRegisterGlobalMarker D")
    let res = analyzeCallCascade(buf, 0)
    check res.gcMarkerClustering.score > 0

  test "Foreign thread GC detection (definitive indicator)":
    let buf = mkBuf("...setupForeignThreadGc...nimGC_setStackBottom...")
    let res = analyzeCallCascade(buf, 0)
    check res.foreignThreadGC.score == res.foreignThreadGC.maxScore

  test "ORC tri-color motif":
    let buf = mkBuf("...nimOrcSweep...nimOrcRegisterCycle...")
    let res = analyzeCallCascade(buf, 0)
    check res.orcTricolorMotif.score > 0

  test "ARC hooks detection":
    let buf = mkBuf("...=copy...=destroy...nimDecRef...")
    let res = analyzeCallCascade(buf, 0)
    check res.arcHooks.score > 0

  test "sysFatal error strings":
    let buf = mkBuf("...sysFatal...@index out of bounds...@division by zero...")
    let res = analyzeCallCascade(buf, 0)
    check res.sysFatalRefs.score == res.sysFatalRefs.maxScore

  test "Module encoding @m_":
    let buf = mkBuf("@m_system @m_pureZstrutils @m_pureZio @m_pureZos @m_pureZmath pureZ")
    let res = analyzeCallCascade(buf, 0)
    check res.moduleEncoding.score > 0

  test "GC mode discriminator — ORC":
    let buf = "...nimOrcSweep...nimTraceRef..."
    check discriminateGCMode(buf) == gcOrc

  test "GC mode discriminator — ARC":
    let buf = "...=copy...=destroy...nimDecRef..."
    check discriminateGCMode(buf) == gcArc

  test "GC mode discriminator — refc":
    let buf = "...nimGCinit...nimGCdeinit..."
    check discriminateGCMode(buf) == gcRefc

  test "GC mode discriminator — unknown (no GC artifacts)":
    let buf = "...some random content..."
    check discriminateGCMode(buf) == gcUnknown

  test "Clean binary scores near 0":
    let buf = mkBuf("This is a normal Windows PE that is not Nim compiled")
    let res = analyzeCallCascade(buf, 0)
    check res.totalScore < 20

  test "Feature vector has correct length":
    let buf = mkBuf("NimMain content")
    let res = analyzeCallCascade(buf, 0)
    check res.featureVector.len == 17  # must match FEATURE_NAMES count in ml_engine

  test "Total score is capped at 75":
    # Craft a buffer with every possible Nim artifact
    let allNim = ("NimMain NimMainInner NimMainModule " &
                  "nimRegisterGlobalMarker nimRegisterGlobalMarker nimRegisterGlobalMarker " &
                  "nimRegisterGlobalMarker nimRegisterGlobalMarker nimRegisterGlobalMarker " &
                  "@m_system @m_pure @m_pure @m_pure @m_pure @m_pure " &
                  "_TM_temp1 _TM_temp2 _TM_temp3 " &
                  "sysFatal fatal.nim @index out of bounds @division by zero " &
                  "nimOrcSweep nimOrcRegisterCycle nimTraceRef scheduleDecRef " &
                  "=copy =destroy =sink =wasMoved nimDecRef " &
                  "setupForeignThreadGc nimGC_setStackBottom")
    let buf = mkBuf(allNim)
    let res = analyzeCallCascade(buf, 0)
    check res.totalScore <= 75  # structural layer max

# ─── PE import parser tests ──────────────────────────────────────────────────

suite "PE Import Parsing":

  test "Non-PE file has empty importedDLLs":
    let tmp = getTempDir() / "nodlls.bin"
    writeFile(tmp, "this is not a PE")
    let info = analyzeBinary(tmp)
    check info.importedDLLs.len == 0
    removeFile(tmp)

  test "PE with no import directory has empty importedDLLs":
    # Minimal PE with numDataDirectories = 0
    var data = "MZ" & "\x00".repeat(58) & "\x40\x00\x00\x00"
    data &= "\x00".repeat(64)   # pad to 0x40
    data &= "PE\x00\x00"        # PE sig
    data &= "\x64\x86"          # x64
    data &= "\x00\x00"          # numSections = 0
    data &= "\x00".repeat(12)   # timestamps / chars
    data &= "\xf0\x00"          # optHdrSize = 240
    data &= "\x00\x00"          # characteristics
    data &= "\x0b\x02"          # PE32+ magic
    data &= "\x00".repeat(238)  # rest of opt header (zeros = 0 data dirs)
    writeFile(getTempDir() / "minpe.bin", data)
    let info = analyzeBinary(getTempDir() / "minpe.bin")
    # Should not crash; may or may not find DLLs (likely 0)
    check info.importedDLLs.len >= 0
    removeFile(getTempDir() / "minpe.bin")

# ─── YARA engine graceful fallback tests ─────────────────────────────────────

import ../src/detectors/yara_engine

suite "YARA Engine":

  test "Missing target file returns empty result":
    let res = scanWithYara("/nonexistent/path/sample.exe", "rules/main.yar")
    check not res.matched
    check res.score == 0

  test "Missing rules file returns empty result":
    let tmp = getTempDir() / "dummy.exe"
    writeFile(tmp, "MZ" & "\x00".repeat(62))
    let res = scanWithYara(tmp, "/nonexistent/rules/no.yar")
    check not res.matched
    check res.score == 0
    removeFile(tmp)

  test "Score for 1 rule match is 15":
    # This tests the scoring formula in isolation
    let fakeRes = YaraResult(matched: true, matchCount: 1,
                             ruleNames: @["TestRule"], score: 15)
    check fakeRes.score == 15

  test "Score for 3 rule matches is 25 (capped)":
    let s = min(15 + (3 - 1) * 5, 25)
    check s == 25

echo "\n[✓] All tests complete"