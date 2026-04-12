/*
  nim_families.yar — NimHunter YARA rules
  Known Nim malware family fingerprints:
  NimzaLoader, HabitsRAT, NimBlackout, and generic Nim stager patterns
*/

rule NimzaLoader_Artifacts {
    meta:
        description = "Detects NimzaLoader — Nim-based loader for BazarBackdoor"
        author      = "NimHunter"
        date        = "2026-04-01"
        reference   = "https://unit42.paloaltonetworks.com/unit42-nimzaloader"
        family      = "NimzaLoader"

    strings:
        // NimzaLoader typically uses gc:arc + WinHTTP
        $arc_copy    = "=copy"        ascii fullword
        $arc_destroy = "=destroy"     ascii fullword
        $winhttp     = "winhttp.dll"  ascii nocase
        $nim_main    = "NimMain"      ascii
        $nim_inner   = "NimMainInner" ascii
        // Loader strings seen in samples
        $loader1     = "VirtualAlloc"  ascii
        $loader2     = "CreateThread"  ascii

    condition:
        uint16(0) == 0x5A4D and
        ($nim_main and $nim_inner) and
        ($arc_copy or $arc_destroy) and
        ($winhttp or ($loader1 and $loader2))
}

rule HabitsRAT_Nim {
    meta:
        description = "Detects HabitsRAT — cross-platform Nim RAT"
        author      = "NimHunter"
        date        = "2026-04-01"
        family      = "HabitsRAT"

    strings:
        $nim_main     = "NimMain"              ascii
        $foreign_gc   = "setupForeignThreadGc" ascii
        $socket_str   = "socket"               ascii
        $recv_str     = "recv"                 ascii fullword
        $send_str     = "send"                 ascii fullword

    condition:
        uint16(0) == 0x5A4D and
        $nim_main and $foreign_gc and
        2 of ($socket_str, $recv_str, $send_str)
}

rule Nim_Generic_Stager {
    meta:
        description = "Generic Nim stager / downloader pattern"
        author      = "NimHunter"
        date        = "2026-04-01"
        confidence  = "medium"

    strings:
        $nim_main    = "NimMain"       ascii
        $nim_module  = "NimMainModule" ascii
        $url_http    = "http://"       ascii nocase
        $url_https   = "https://"      ascii nocase
        $alloc       = "VirtualAlloc"  ascii
        $exec        = "CreateRemoteThread" ascii

    condition:
        uint16(0) == 0x5A4D and
        ($nim_main and $nim_module) and
        1 of ($url_http, $url_https) and
        1 of ($alloc, $exec)
}

rule Nim_Blackout_Driver_Killer {
    meta:
        description = "Detects NimBlackout — Nim-based EDR driver killer"
        author      = "NimHunter"
        date        = "2026-04-01"
        family      = "NimBlackout"

    strings:
        $nim_main   = "NimMain"            ascii
        $driver     = "\\\\.\\PhysicalDrive" ascii wide
        $ntdll      = "ntdll.dll"          ascii nocase
        $ioctl      = "DeviceIoControl"    ascii

    condition:
        uint16(0) == 0x5A4D and
        $nim_main and $driver and
        ($ntdll or $ioctl)
}
