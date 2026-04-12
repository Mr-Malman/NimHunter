# Package
version       = "2.0.0"
author        = "Arya"
description   = "Nim-based detection tool"
license       = "MIT"
srcDir        = "src"
bin           = @["nimhunter"]

# Dependencies
requires "nim >= 2.0.0"
# Future: requires "https://github.com/dmknght/nimyara"  # native YARA bindings (not yet wired)
# Future: requires "capstone"                             # disassembly (not yet wired)
# Future: requires "peni"                                 # PE inspection helper