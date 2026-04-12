## demangler.nim
## Nim symbol name demangler and forensic path extractor for NimHunter v2
## Implements full @m_ module encoding decoder and developer path leak detection

import strutils, re

type
  DemangledSymbol* = object
    original*:     string
    functionName*: string
    modulePath*:   string
    packagePath*:  string
    version*:      int
    isStdlib*:     bool
    isThirdParty*: bool
    isModuleInit*: bool

  ForensicPaths* = object
    developerPaths*: seq[string]  ## Absolute paths leaked from the attacker's system
    packageNames*:   seq[string]  ## Third-party Nim package names
    nimVersion*:     string       ## Nim version inferred from stdlib path
    moduleNames*:    seq[string]  ## Decoded @m_ module names from binary

# ─── Path decoding ───────────────────────────────────────────────────────────

proc decodePathZ(encoded: string): string =
  ## Decode Nim's Z-based path encoding (Z -> /, ZZ -> literal Z)
  result = ""
  var i = 0
  while i < encoded.len:
    if encoded[i] == 'Z':
      if i + 1 < encoded.len and encoded[i+1] == 'Z':
        result.add('Z')
        inc i, 2
      else:
        result.add('/')
        inc i
    else:
      result.add(encoded[i])
      inc i

proc extractVersion(name: string): int =
  ## Extract _u#### version suffix
  let m = name.find(re"_u(\d+)$")
  if m >= 0:
    let numStr = name[m+2..^1]
    try: return parseInt(numStr)
    except: return -1
  return -1

# ─── Main demangle procedure ─────────────────────────────────────────────────

proc demangle*(mangledName: string): DemangledSymbol =
  var sym = DemangledSymbol(original: mangledName, version: -1)
  var name = mangledName

  # Strip version suffix
  sym.version = extractVersion(name)
  name = name.replace(re"_u\d+$", "")

  # @m_ = module initializer (top-level module code)
  if name.startsWith("@m_"):
    sym.isModuleInit = true
    let encoded = name[3..^1]
    sym.modulePath = decodePathZ(encoded)
    sym.functionName = "<module_init>"
    sym.isStdlib = "nim/" in sym.modulePath or
                   "stdlib" in sym.modulePath or
                   "pure/" in sym.modulePath
    sym.isThirdParty = not sym.isStdlib and
                       ("/" in sym.modulePath or sym.modulePath.len > 0)
    if sym.isThirdParty and "/" in sym.modulePath:
      sym.packagePath = sym.modulePath.split("/")[0]
    return sym

  # Standard mangling: functionName__modulePathEncoded
  if "__" in name:
    let splitIdx = name.find("__")
    sym.functionName = name[0..splitIdx-1]
    let pathEncoded  = name[splitIdx+2..^1]
    sym.modulePath   = decodePathZ(pathEncoded)

    sym.isStdlib = "pure" in sym.modulePath or
                   "system" in sym.modulePath or
                   "stdlib" in sym.modulePath or
                   sym.modulePath.startsWith("nim/") or
                   "nim-" in sym.modulePath

    sym.isThirdParty = not sym.isStdlib and "/" in sym.modulePath
    if sym.isThirdParty and "/" in sym.modulePath:
      sym.packagePath = sym.modulePath.split("/")[0]
    return sym

  # Unmangled symbol
  sym.functionName = name
  return sym

# ─── Batch scanner for binary content ────────────────────────────────────────

proc decodeModuleNames*(buffer: string): seq[string] =
  ## Scan binary content for @m_ patterns and decode all module names found
  result = @[]
  var i = 0
  while i < buffer.len - 3:
    if buffer[i] == '@' and buffer[i+1] == 'm' and buffer[i+2] == '_':
      var raw = ""
      var j = i + 3
      while j < buffer.len and j < i + 200:
        let c = ord(buffer[j])
        # Stop at null, space, newline, or non-printable
        if c == 0 or c == 32 or c == 10 or c == 13 or c < 32: break
        raw.add(char(c))
        inc j
      if raw.len >= 2:
        let decoded = decodePathZ(raw)
        if decoded notin result:
          result.add(decoded)
    inc i

proc extractForensicPaths*(buffer: string): ForensicPaths =
  ## Extract all forensic path artifacts from a binary buffer
  ## These reveal the attacker's development environment structure
  var fp = ForensicPaths()
  let modules = decodeModuleNames(buffer)
  fp.moduleNames = modules

  for m in modules:
    # Nim version detection from stdlib paths
    if "nim-" in m and fp.nimVersion == "":
      let parts = m.split("/")
      for p in parts:
        if p.startsWith("nim-"):
          fp.nimVersion = p

    # Developer absolute paths (Windows: C:\Users\, Linux: /home/)
    if ("C:" in m or "/home/" in m or "/Users/" in m) and m notin fp.developerPaths:
      fp.developerPaths.add(m)

    # Third-party packages (non-stdlib paths without absolute prefix)
    if "/" in m and "nim/" notin m and "pure/" notin m and "system" notin m:
      let pkg = m.split("/")[0]
      if pkg.len > 0 and pkg notin fp.packageNames:
        fp.packageNames.add(pkg)

  return fp

when isMainModule:
  echo demangle("toHex__pureZstrutils_u2067").modulePath  # pure/strutils
  echo demangle("@m_ZhomeZuserZprojectsZratZmain_u1").modulePath  # /home/user/projects/rat/main