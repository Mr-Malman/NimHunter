/*
  nim_arc.yar — NimHunter YARA rules
  Detects ARC (Automatic Reference Counting) garbage collector artifacts
  unique to Nim binaries compiled with --gc:arc
*/

rule Nim_ARC_GarbageCollector {
    meta:
        description = "Detects Nim ARC move-semantics memory management hooks"
        author      = "NimHunter"
        date        = "2026-04-01"
        layer       = "1"
        confidence  = "high"

    strings:
        $arc_copy     = "=copy"         ascii fullword
        $arc_destroy  = "=destroy"      ascii fullword
        $arc_sink     = "=sink"         ascii fullword
        $arc_trace    = "=trace"        ascii fullword
        $arc_moved    = "=wasMoved"     ascii fullword
        $arc_decref   = "nimDecRef"     ascii
        $arc_raw_new  = "nimRawNewObj"  ascii
        $arc_new_obj  = "nimNewObj"     ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            ($arc_copy and $arc_destroy) or
            ($arc_sink and $arc_decref)  or
            2 of ($arc_*)
        )
}

rule Nim_REFC_GarbageCollector {
    meta:
        description = "Detects Nim legacy gc:refc runtime (older malware families)"
        author      = "NimHunter"
        date        = "2026-04-01"
        confidence  = "medium"

    strings:
        $gc_init  = "nimGCinit"   ascii
        $gc_deinit = "nimGCdeinit" ascii

    condition:
        uint16(0) == 0x5A4D and
        all of them
}
