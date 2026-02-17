import os, osproc, strutils

proc scanWithYara*(filePath: string, rulesPath: string): bool =
  ## Scans a file using yara command-line tool and returns true if matches found
  try:
    # Check if yara is installed
    let (output, exitCode) = execCmdEx("which yara")
    if exitCode != 0:
      echo "[!] YARA tool not found, skipping YARA scan"
      return false
    
    # Run yara command
    let cmd = "yara -r \"" & rulesPath & "\" \"" & filePath & "\""
    let (yaraOutput, _) = execCmdEx(cmd)
    
    if yaraOutput.len > 0 and yaraOutput != "":
      let matches = yaraOutput.split("\n")
      for match in matches:
        if match.len > 0:
          echo "[!] YARA Match Found: " & match
      return true
    
    return false
  except:
    echo "[!] Error running YARA scan"
    return false