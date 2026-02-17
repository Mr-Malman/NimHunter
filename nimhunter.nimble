# Package
version       = "0.1.0"
author        = "Arya"
description   = "Nim-based detection tool"
license       = "MIT"
srcDir        = "src"
bin           = @["nimhunter"]

# Dependencies
requires "nim >= 2.0.0"
# requires "peni"
requires "https://github.com/dmknght/nimyara"
requires "capstone"