rule MAL_BURNTCIGAR_Strings {
strings:
$s0 = "!This program cannot be run in DOS mode."
$s1 = "CorExitProcess"
$s2 = "Kill PID ="
$s3 = "CreateFile Error = "
$pdb = "F:\\Source\\WorkNew19\\KillAV\\Release\\KillAV.pdb"
$s5 = "SentinelHelperService.exe" wide
$s6 = "SentinelServiceHost.exe" wide
$s7 = "SentinelStaticEngineScanner.exe" wide
$s8 = "Sentinel0Agent.exe" wide
$s9 = "SentinelAgentWorker.exe" wide
$s10 = "SentinelUI.exe" wide
$s11 = "SAVAdminService.exe" wide
$s12 = "SavService.exe" wide
$s13 = "SEDService.exe" wide
$s14 = "ALsvc.exe" wide
$s15 = "SophosCleanM64.exe" wide
$s16 = "SophosFS.exe" wide
$s17 = "SophosFileScanner.exe" wide
$s18 = "SophosHealth.exe" wide
$s19 = "Endpoint Agent Tray.exe" wide
$s20 = "EAServiceMonitor.exe" wide
$s21 = "MsMpEng.exe" wide
$s22 = "\\\\.\\" wide
$s23 = "\\\\.\\aswSP_Avar" wide
condition: 22 of ($s*) or ( $pdb and 15 of ($s*) )
}

import "pe"
rule pe_y0da {
    meta:
        desc = "looks for any PE section with a section name .y0da"
    condition:
        pe.sections.name == ".y0da"
}