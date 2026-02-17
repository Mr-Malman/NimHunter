rule Nim_Compiler_Artifacts {
    meta:
        description = "Detects core Nim compiler artifacts and runtime initialization"
        author = "NimHunter"
        date = "2026-02-17"
        layer = "1"

    strings:
        // Core initialization functions
        $nim_main = "NimMain" ascii fullword
        $nim_inner = "NimMainInner" ascii fullword
        $nim_module = "NimMainModule" ascii fullword

        // Error handling artifacts (highly reliable)
        $sys_fatal = "sysFatal" ascii fullword
        $fatal_nim = "fatal.nim" ascii fullword
        
        // Runtime error messages
        $err1 = "@value out of range" ascii
        $err2 = "@division by zero" ascii
        $err3 = "@index out of bounds" ascii

    condition:
        uint16(0) == 0x5A4D and // Must be a PE file
        (
            2 of ($nim_*) or 
            all of ($sys_fatal, $fatal_nim) or
            2 of ($err*)
        )
}

rule Nim_Mangled_Strings {
    meta:
        description = "Detects Nim's unique name mangling patterns"
    
    strings:
        // Matches the 'pure' library marker and 'u' versioning suffix
        $mangling = /_[a-zA-Z0-9]+__pureZ[a-zA-Z0-9]+_u[0-9]+/
        $string_prefix = "_TM" ascii // Nim's internal temporary variable prefix

    condition:
        uint16(0) == 0x5A4D and any of them
}