import std/[re, strutils]

proc demangle*(mangledName: string): string =
  ## Decodes Nim mangled names (e.g., toHex__pureZstrutils_u2067 -> strutils:toHex)
  
  # 1. Strip the hash/version suffix (e.g., _u2067)
  var name = mangledName.replace(re"_u[0-9]+$", "")
  
  # 2. Identify the module/function split (Nim uses double underscore __)
  if "__" in name:
    let parts = name.split("__")
    let funcName = parts[0]
    # Replace 'Z' with '/' or ':' for pathing
    let modulePath = parts[1].replace("Z", ":")
    return modulePath & ":" & funcName
  
  return name

# Quick test logic
if isMainModule:
  echo demangle("toHex__pureZstrutils_u2067") # Output: pure:strutils:toHex