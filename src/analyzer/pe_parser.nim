## pe_parser.nim
## Full PE binary parser for NimHunter v2
## Extracts architecture, sections, entropy, TLS, and Nim-specific string structs

import os, math, strutils

type
  PESection* = object
    name*:           string
    virtualAddress*: uint32
    virtualSize*:    uint32
    rawOffset*:      uint32
    rawSize*:        uint32
    entropy*:        float
    isExecutable*:   bool
    isWritable*:     bool

  NimStringArtifact* = object
    offset*:  uint32
    content*: string

  PEInfo* = object
    isPE*:           bool
    arch*:           string
    entryPoint*:     uint32
    imageBase*:      uint64
    sections*:       seq[PESection]
    hasTLS*:         bool
    hasDebugDir*:    bool
    isStripped*:     bool
    isPacked*:       bool
    overallEntropy*: float
    nimStrings*:     seq[NimStringArtifact]
    tmStringCount*:  int
    importedDLLs*:   seq[string]

# ─── Low-level readers ───────────────────────────────────────────────────────

proc readU16(data: string, off: int): uint16 =
  if off + 2 > data.len: return 0
  uint16(ord(data[off])) or (uint16(ord(data[off+1])) shl 8)

proc readU32(data: string, off: int): uint32 =
  if off + 4 > data.len: return 0
  uint32(ord(data[off])) or
  (uint32(ord(data[off+1])) shl 8) or
  (uint32(ord(data[off+2])) shl 16) or
  (uint32(ord(data[off+3])) shl 24)

proc readU64(data: string, off: int): uint64 =
  if off + 8 > data.len: return 0
  uint64(readU32(data, off)) or (uint64(readU32(data, off+4)) shl 32)

proc readCString(data: string, off: int, maxLen: int = 256): string =
  ## Read a null-terminated C string from the given offset
  result = ""
  var i = off
  while i < data.len and i < off + maxLen:
    let c = ord(data[i])
    if c == 0: break
    result.add(char(c))
    inc i

proc rvaToRaw(rva: uint32, sections: seq[PESection]): int =
  ## Convert a Relative Virtual Address to a raw file offset using the section table
  for sec in sections:
    if rva >= sec.virtualAddress and rva < sec.virtualAddress + sec.virtualSize:
      return int(rva - sec.virtualAddress + sec.rawOffset)
  return -1

# ─── Entropy calculation ─────────────────────────────────────────────────────

proc calcEntropy*(data: string, offset: int = 0, length: int = -1): float =
  let endIdx = if length < 0: data.len else: min(offset + length, data.len)
  let n = endIdx - offset
  if n == 0: return 0.0
  var freq: array[256, int]
  for i in offset ..< endIdx:
    inc freq[ord(data[i])]
  result = 0.0
  let nf = float(n)
  for f in freq:
    if f > 0:
      let p = float(f) / nf
      result -= p * log2(p)

# ─── _TM Nim string artifact scanner ─────────────────────────────────────────

proc scanNimStrings(data: string, sec: PESection): seq[NimStringArtifact] =
  result = @[]
  if sec.rawOffset == 0 or sec.rawSize == 0: return
  let start = int(sec.rawOffset)
  let stop  = min(start + int(sec.rawSize), data.len - 4)
  var i = start
  while i < stop:
    # _TM prefix (Nim temporary variable strings)
    if i + 3 < data.len and
       data[i] == '_' and data[i+1] == 'T' and data[i+2] == 'M':
      var content = ""
      var j = i
      while j < stop and j < i + 80:
        let c = ord(data[j])
        if c == 0: break
        if c < 32 and c notin [9, 10, 13]: break
        content.add(char(c))
        inc j
      if content.len >= 3:
        result.add(NimStringArtifact(offset: uint32(i), content: content))
    inc i

# ─── Main parser ─────────────────────────────────────────────────────────────

proc analyzeBinary*(path: string): PEInfo =
  var info = PEInfo(isPE: false, arch: "unknown")

  try:
    let raw = readFile(path)
    if raw.len < 64: return info

    # MZ magic
    if raw[0] != 'M' or raw[1] != 'Z': return info
    info.isPE = true

    # PE offset
    let peOff = int(readU32(raw, 0x3C))
    if peOff + 24 >= raw.len: return info

    # PE signature
    if raw[peOff..peOff+3] != "PE\x00\x00": return info

    # COFF header
    let machine     = readU16(raw, peOff + 4)
    let numSections = int(readU16(raw, peOff + 6))
    let optHdrSize  = int(readU16(raw, peOff + 20))
    let charact     = readU16(raw, peOff + 22)
    info.isStripped = (charact and 0x0200'u16) != 0

    case machine
    of 0x8664'u16: info.arch = "x64"
    of 0x014C'u16: info.arch = "x86"
    of 0xAA64'u16: info.arch = "ARM64"
    else: info.arch = "unknown"

    let optStart = peOff + 24
    let magic    = readU16(raw, optStart)
    let is64     = magic == 0x020B'u16

    info.entryPoint = readU32(raw, optStart + 16)
    info.imageBase  = if is64: readU64(raw, optStart + 24)
                      else: uint64(readU32(raw, optStart + 28))

    # Data directory offsets
    let ddBase     = optStart + (if is64: 112 else: 96)
    let numDDs     = int(readU32(raw, optStart + (if is64: 108 else: 92)))
    if numDDs > 9:
      info.hasTLS      = readU32(raw, ddBase + 9*8) != 0
    if numDDs > 6:
      info.hasDebugDir = readU32(raw, ddBase + 6*8) != 0

    # Import directory (DLL names) — parsed after section table is built
    # (stored for post-section-parse step below)
    let impRVA = if numDDs > 1: readU32(raw, ddBase + 1*8) else: 0'u32

    # Section table
    let secTableStart = optStart + optHdrSize
    for i in 0 ..< numSections:
      let sOff = secTableStart + i * 40
      if sOff + 40 > raw.len: break

      var secName = ""
      for j in 0 ..< 8:
        let c = ord(raw[sOff + j])
        if c == 0: break
        secName.add(char(c))

      let vAddr   = readU32(raw, sOff + 12)
      let vSize   = readU32(raw, sOff + 8)
      let rawOff  = readU32(raw, sOff + 20)
      let rawSz   = readU32(raw, sOff + 16)
      let flags   = readU32(raw, sOff + 36)

      let secEntropy =
        if rawOff > 0 and rawSz > 0 and int(rawOff) + int(rawSz) <= raw.len:
          calcEntropy(raw, int(rawOff), int(rawSz))
        else: 0.0

      let sec = PESection(
        name:           secName,
        virtualAddress: vAddr,
        virtualSize:    vSize,
        rawOffset:      rawOff,
        rawSize:        rawSz,
        entropy:        secEntropy,
        isExecutable:   (flags and 0x20000000'u32) != 0,
        isWritable:     (flags and 0x80000000'u32) != 0
      )
      info.sections.add(sec)

      # Scan .rdata / .data for _TM Nim string artifacts
      if secName in [".rdata", ".data", "rdata", "data"]:
        let found = scanNimStrings(raw, sec)
        info.nimStrings.add(found)
        info.tmStringCount += found.len

    # Overall file entropy
    info.overallEntropy = calcEntropy(raw)

    # Heuristic: packed if high entropy .text or small section count with high entropy
    for sec in info.sections:
      if sec.isExecutable and sec.entropy > 7.2:
        info.isPacked = true

    # Parse import directory table (needs sections to be built first)
    if impRVA != 0:
      var descOff = rvaToRaw(impRVA, info.sections)
      # IMAGE_IMPORT_DESCRIPTOR is 20 bytes; end sentinel has all zeros
      while descOff >= 0 and descOff + 20 <= raw.len:
        let nameRVA = readU32(raw, descOff + 12)
        if nameRVA == 0: break  # sentinel
        let nameOff = rvaToRaw(nameRVA, info.sections)
        if nameOff >= 0 and nameOff < raw.len:
          let dllName = readCString(raw, nameOff)
          if dllName.len > 0 and dllName notin info.importedDLLs:
            info.importedDLLs.add(dllName)
        descOff += 20

    return info
  except:
    return info