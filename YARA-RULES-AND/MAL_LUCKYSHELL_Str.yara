rule MAL_LUCKYSHELL_Str {
    strings:
    $a1 = "injectluck.dll"
    $b1 = "luckyshell.ini"
    $b2 = "lucky_tmp_log.ini"
    $z1 = "Win32/LuckyShell.B"
    $z2 = "Win32/Trojan.Gen"
    $z3 = "MAL_LUCKYSHELL"
    condition:
    $a and ($b1 or $b2) and none of ($z*)
}