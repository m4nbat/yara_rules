import "pe"
rule ttp_versioninfo_microsoft_delphi {
    meta:
        author = "manb4t"
    condition:
        pe.number_of_signatures > 0
        and pe.version_info["CompanyName"]
            icontains "Microsoft" and
    // Delphi compiler default timestamp
    // 708992537, Fri 19 JUne 1992 22:22:17 UTC
            pe.timestamp == 0x2A425E19
}