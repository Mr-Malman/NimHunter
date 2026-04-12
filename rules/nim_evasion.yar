/*
  nim_evasion.yar — NimHunter YARA rules
  Detects Nim malware evasion and injection artifacts:
  foreign thread GC setup, module init encoding, shellcode loader patterns
*/

rule Nim_ForeignThread_Injection {
    meta:
        description = "Detects Nim payload injected into a foreign (non-Nim) thread"
        author      = "NimHunter"
        date        = "2026-04-01"
        layer       = "1"
        confidence  = "definitive"
        reference   = "setupForeignThreadGc is REQUIRED for any Nim code running in an injected thread"

    strings:
        $foreign_setup    = "setupForeignThreadGc"    ascii
        $foreign_teardown = "teardownForeignThreadGc" ascii
        $stack_bottom     = "nimGC_setStackBottom"    ascii
        $thread_vars      = "nimThreadVarsInit"       ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            $foreign_setup or
            $stack_bottom  or
            ($foreign_teardown and $thread_vars)
        )
}

rule Nim_Module_Init_Encoding {
    meta:
        description = "Detects Nim @m_ module initializer Z-path encoding"
        author      = "NimHunter"
        date        = "2026-04-01"
        layer       = "1"

    strings:
        $m_enc1 = "@m_" ascii
        $m_enc2 = "pureZ" ascii          // stdlib path encoding
        $m_enc3 = /\@m_[A-Za-z0-9_]+Z/  // @m_ followed by path-encoded name

    condition:
        uint16(0) == 0x5A4D and
        (
            ($m_enc1 and $m_enc2) or
            $m_enc3
        )
}

rule Nim_TLS_Thread_Storage {
    meta:
        description = "Detects Nim runtime TLS usage (common in Nim RATs and loaders)"
        author      = "NimHunter"
        date        = "2026-04-01"

    strings:
        $tls_alloc = "nimTlsAlloc"   ascii
        $tls_free  = "nimTlsFree"    ascii
        $tls_set   = "nimTlsSet"     ascii
        $tls_get   = "nimTlsGet"     ascii

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}
