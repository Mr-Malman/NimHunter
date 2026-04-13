## make_samples.nim
## NimHunter — Test Sample Generator
##
## Compiles small Nim programs and saves them as test PE binaries in data/samples/
## Run with: nim r data/make_samples.nim
##
## REQUIREMENTS: Windows (cross-compilation) OR nim with mingw-w64 cross-compiler
## On macOS/Linux: nim c --os:windows --cpu:amd64 --cc:gcc ...  (needs mingw-w64)
##
## Quick one-liner to cross-compile for Windows from macOS:
##   brew install mingw-w64
##   nim c -d:mingw --os:windows --cpu:amd64 -o:data/samples/nim_rc.exe <source>

import os, osproc, strutils

const SAMPLES_DIR = "data/samples"

# ── Sample source code snippets ───────────────────────────────────────────────

const srcSimple = """
## nim_simple.nim — Minimal Nim program (gc:refc, no threads)
echo "Hello from Nim"
let x = 42
echo "Answer: " & $x
"""

const srcORC = """
## nim_orc.nim — Nim with ORC GC (gc:orc, heap cycles)
type Node = ref object
  val:  int
  next: Node

var head = Node(val: 1)
head.next = Node(val: 2)
head.next.next = head   # cycle — requires ORC to collect

echo "ORC sample running, GC mode: orc"
"""

const srcARC = """
## nim_arc.nim — Nim with ARC (gc:arc, no cycles)
import strutils

proc greet(name: string): string =
  result = "Hello, " & name & "!"

echo greet("ARC sample")
"""

const srcLoader = """
## nim_loader.nim — Nim with Windows API calls (shellcode loader pattern)
import winim

proc main() =
  let mem = VirtualAlloc(nil, 4096, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE)
  if mem == nil:
    echo "VirtualAlloc failed"
    return
  echo "Loader sample — simulated shellcode allocation"
  VirtualFree(mem, 0, MEM_RELEASE)

main()
"""

const srcThreaded = """
## nim_threaded.nim — Nim with foreign thread GC setup
import os, threadpool

proc worker() {.thread.} =
  echo "Thread " & $getThreadId() & " running"

var thr: Thread[void]
createThread(thr, worker)
joinThread(thr)
echo "Main done"
"""

# ── Compiler target configurations ────────────────────────────────────────────

type SampleSpec = object
  name:    string
  src:     string
  gcMode:  string
  extra:   string

const SPECS: seq[SampleSpec] = @[
  SampleSpec(name: "nim_simple_refc",    src: srcSimple,   gcMode: "refc",   extra: ""),
  SampleSpec(name: "nim_simple_arc",     src: srcARC,      gcMode: "arc",    extra: ""),
  SampleSpec(name: "nim_simple_orc",     src: srcORC,      gcMode: "orc",    extra: ""),
  SampleSpec(name: "nim_threaded_arc",   src: srcThreaded, gcMode: "arc",    extra: ""),
]

proc crossCompileWindows(spec: SampleSpec, outDir: string): bool =
  ## Attempt cross-compilation to Windows PE using mingw-w64
  ## Returns true on success
  let srcFile = outDir / spec.name & ".nim"
  let outFile = outDir / spec.name & ".exe"

  writeFile(srcFile, spec.src)

  let cmd = "nim c" &
    " --os:windows --cpu:amd64" &
    " --cc:gcc" &
    " --gcc.exe:x86_64-w64-mingw32-gcc" &
    " --gcc.linkerexe:x86_64-w64-mingw32-gcc" &
    " --gc:" & spec.gcMode &
    " -d:release --opt:speed" &
    " -o:\"" & outFile & "\"" &
    " \"" & srcFile & "\"" &
    " 2>&1"

  echo "[*] Building: " & spec.name & ".exe  (gc:" & spec.gcMode & ")"
  let (output, code) = execCmdEx(cmd)
  if code == 0:
    echo "[+] OK → " & outFile
    return true
  else:
    echo "[!] FAILED: " & spec.name
    echo output
    return false

when isMainModule:
  createDir(SAMPLES_DIR)

  echo """
╔══════════════════════════════════════════════════════╗
║        NimHunter — Test Sample Generator             ║
╠══════════════════════════════════════════════════════╣
║ Requires: mingw-w64 cross-compiler                   ║
║ macOS:  brew install mingw-w64                       ║
║ Linux:  apt install gcc-mingw-w64-x86-64             ║
╚══════════════════════════════════════════════════════╝

NOTE: If cross-compilation fails, see SAMPLES.md for
      alternative ways to get test PE binaries.
"""

  # Check for mingw cross-compiler
  let (_, mingwCheck) = execCmdEx("which x86_64-w64-mingw32-gcc 2>/dev/null")
  if mingwCheck != 0:
    echo "[!] x86_64-w64-mingw32-gcc not found."
    echo "    Install with: brew install mingw-w64  (macOS)"
    echo "                  apt install gcc-mingw-w64  (Linux)"
    echo ""
    echo "    Alternatively, see data/SAMPLES.md for other options."
    quit(1)

  var ok = 0
  var fail = 0
  for spec in SPECS:
    if crossCompileWindows(spec, SAMPLES_DIR): inc ok
    else: inc fail

  echo ""
  echo "[*] Done: " & $ok & " succeeded, " & $fail & " failed"
  echo "[*] Samples in: " & SAMPLES_DIR
