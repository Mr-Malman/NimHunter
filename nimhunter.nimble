version       = "0.1.0"
author        = "YourName"
description   = "Nim-based detection tool for Nim malware signatures"
license       = "MIT"
srcDir        = "src"
bin           = @["nimhunter"]

# Dependencies
requires "nim >= 2.0.0"
requires "peni"            # For PE parsing
requires "yara"            # Nim YARA bindings
requires "capstone"        # Disassembly
requires "arraymancer"     # For future ML inference