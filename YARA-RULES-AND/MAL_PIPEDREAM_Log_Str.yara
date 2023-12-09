import "pe"
rule MAL_PIPEDREAM_Log_Str {
    strings:
    $header = "MZ"
    $a1 = "C:\\ProgramData\\tmp.log" ascii wide
    $a2 = "C:\\ProgramData\\temp.log" ascii wide
    condition:
    
    $header at 0

    and

    any of ($a*)
        in (filesize-5000..filesize)
}