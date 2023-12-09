import "pe"
import "console"
rule mal_exelastealer {
    meta:
        author = "manb4t"
        sha256 = "ccb1337383351bb6889eb8478c18c0142cb99cbb523acc85d0d626d323f5d7ad"
        description = "Detects Exela Stealer"
    condition:
        true
}
rule mal_exelastealer_pe_version_info {
    meta:
        author = "manb4t"
        sha256 = "ccb1337383351bb6889eb8478c18c0142cb99cbb523acc85d0d626d323f5d7ad"
        description = "Detects Exela Stealer"
        date = "2023-10-26"
    condition:
        pe.version_info["CompanyName"] == "Exela Corporation" and
        pe.version_info["FileDescription"] == "Exela Update Service" and
        pe.version_info["InternalName"] == "Exela.exe" and
        pe.version_info["LegalCopyright"] == "\xa9 Exela Corporation. All rights reserved."

}
rule exela_stealer {
    meta:
        author = "Cyble"
        description = "Detects Exela Stealer"
        date = "2023-09-25"
        os = "Windows"
        threat_name = "Exela Stealer"
        scan_type = "file"
        severity = 90
        reference_sample = "ccb1337383351bb6889eb8478c18c0142cb99cbb523acc85d0d626d323f5d7ad"
    strings:
        $a = "Exela Corporation" ascii wide
        $b = "Exela Update Service" ascii wide
        $c = "Exela.exe" ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}