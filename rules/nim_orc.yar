/*
  nim_orc.yar — NimHunter YARA rules
  Detects ORC (Ownership Reference Counting) garbage collector artifacts
  unique to Nim binaries compiled with --gc:orc
*/

rule Nim_ORC_GarbageCollector {
    meta:
        description = "Detects Nim ORC (cycle-aware RC) garbage collector runtime"
        author      = "NimHunter"
        date        = "2026-04-01"
        layer       = "1"
        confidence  = "high"

    strings:
        $orc_sweep    = "nimOrcSweep"           ascii
        $orc_cycle    = "nimOrcRegisterCycle"   ascii
        $orc_trace    = "nimTraceRef"           ascii
        $orc_decref   = "scheduleDecRef"        ascii
        $trial_del    = "trialDelete"           ascii
        $cyc_col      = "cyclecollector"        ascii

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule Nim_ORC_Definitive {
    meta:
        description = "Definitive ORC: sweep + cycle registration both present"
        author      = "NimHunter"
        confidence  = "definitive"

    strings:
        $orc_sweep  = "nimOrcSweep"         ascii
        $orc_cycle  = "nimOrcRegisterCycle" ascii

    condition:
        uint16(0) == 0x5A4D and
        all of them
}
