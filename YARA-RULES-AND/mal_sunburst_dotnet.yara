import "dotnet"
import "console"
rule mal_sunburst_1 {
    meta:
        author = "manb4t"
        description = "Rule to detect the Sunburst malware"
        references = "https://www.mandiant.com/resources/blog/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor | https://www.mandiant.com/resources/blog/sunburst-additional-technical-details | https://github.com/mandiant/sunburst_countermeasures/tree/main/rules/SUNBURST/yara"
        sha256 = "019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and
        dotnet.assembly.name == "SolarWinds.Orion.Core.BusinessLayer" and
        console.log("Constants: ",dotnet.constants[0]) and
        dotnet.constants[0] == "A\x00u\x00d\x00i\x00t\x00i\x00n\x00g\x00I\x00n\x00d\x00i\x00c\x00a\x00t\x00i\x00o\x00n\x00s\x00" and
        dotnet.constants[1] == "S\x00o\x00u\x00r\x00c\x00e\x00I\x00n\x00s\x00t\x00a\x00n\x00c\x00e\x00U\x00r\x00i\x00" and
        dotnet.constants[2] == "U\x00r\x00i\x00" and
        dotnet.constants[3] == "o\x00r\x00i\x00o\x00n\x00.\x00s\x00e\x00r\x00v\x00i\x00c\x00e\x00L\x00o\x00c\x00a\x00t\x00o\x00r\x00" and
        dotnet.constants[4] == "O\x00r\x00i\x00o\x00n\x00C\x00o\x00r\x00e\x00I\x00n\x00d\x00i\x00c\x00a\x00t\x00i\x00o\x00n\x00s\x00" and
        dotnet.constants[5] == "N\x00o\x00d\x00e\x00I\x00n\x00d\x00i\x00c\x00a\x00t\x00i\x00o\x00n\x00s\x00" and
        dotnet.constants[6] == "n\x00e\x00t\x00.\x00p\x00i\x00p\x00e\x00:\x00/\x00/\x00l\x00o\x00c\x00a\x00l\x00h\x00o\x00s\x00t\x00/\x00o\x00r\x00i\x00o\x00n\x00/\x00c\x00o\x00r\x00e\x00/\x00s\x00c\x00h\x00e\x00d\x00u\x00l\x00e\x00d\x00d\x00i\x00s\x00c\x00o\x00v\x00e\x00r\x00y\x00j\x00o\x00b\x00s\x00e\x00v\x00e\x00n\x00t\x00s\x002\x00"
}

rule mal_sunburst_2 {
    meta:
        author = "manb4t"
        description = "Rule to detect the Sunburst malware"
        references = "https://www.mandiant.com/resources/blog/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor | https://www.mandiant.com/resources/blog/sunburst-additional-technical-details | https://github.com/mandiant/sunburst_countermeasures/tree/main/rules/SUNBURST/yara"
        sha256 = "019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and
        dotnet.assembly.name == "SolarWinds.Orion.Core.BusinessLayer" and
        dotnet.user_strings[0] == "{\x00{\x00 \x00K\x00e\x00y\x00 \x00=\x00 \x00{\x000\x00}\x00,\x00 \x00V\x00a\x00l\x00u\x00e\x00 \x00=\x00 \x00{\x001\x00}\x00 \x00}\x00}\x00" and
        dotnet.user_strings[1] == "{\x00{\x00 \x00P\x00r\x00o\x00d\x00u\x00c\x00t\x00N\x00a\x00m\x00e\x00 \x00=\x00 \x00{\x000\x00}\x00,\x00 \x00P\x00o\x00l\x00l\x00e\x00r\x00F\x00e\x00a\x00t\x00u\x00r\x00e\x00V\x00a\x00l\x00u\x00e\x00 \x00=\x00 \x00{\x001\x00}\x00 \x00}\x00}\x00" and
        dotnet.user_strings[5] == "a\x00n\x00c\x00" and
        dotnet.user_strings[6] == "m\x00e\x00s\x00s\x00a\x00g\x00e\x00" and
        dotnet.user_strings[7] == "S\x00Y\x00S\x00T\x00E\x00M\x00" and
        dotnet.user_strings[8] == "I\x00n\x00d\x00i\x00c\x00a\x00t\x00i\x00o\x00n\x00T\x00i\x00m\x00e\x00" and
        dotnet.user_strings[9] == "s\x00u\x00b\x00s\x00c\x00r\x00i\x00p\x00t\x00i\x00o\x00n\x00M\x00a\x00n\x00a\x00g\x00e\x00r\x00" and
        dotnet.user_strings[10] == "A\x00c\x00t\x00i\x00o\x00n\x00T\x00y\x00p\x00e\x00" and
        dotnet.user_strings[11] == "A\x00u\x00d\x00i\x00t\x00E\x00v\x00e\x00n\x00t\x00I\x00d\x00" and
        dotnet.user_strings[12] == "I\x00n\x00s\x00t\x00a\x00n\x00c\x00e\x00T\x00y\x00p\x00e\x00" and
        dotnet.user_strings[13] == "O\x00r\x00i\x00o\x00n\x00.\x00A\x00u\x00d\x00i\x00t\x00i\x00n\x00g\x00E\x00v\x00e\x00n\x00t\x00s\x00" and
        dotnet.user_strings[14] == "O\x00r\x00i\x00g\x00i\x00n\x00a\x00l\x00A\x00c\x00c\x00o\x00u\x00n\x00t\x00I\x00d\x00" and
        dotnet.user_strings[15] == "S\x00y\x00s\x00t\x00e\x00m\x00.\x00I\x00n\x00s\x00t\x00a\x00n\x00c\x00e\x00C\x00r\x00e\x00a\x00t\x00e\x00d\x00" and
        dotnet.user_strings[16] == ":\x00 \x00" and
        dotnet.user_strings[17] == "n\x00u\x00l\x00l\x00"
}
 /*                                                       
rule mal_sunburst_2 {
    meta:
       author = "manb4t"
        description = "Rule to detect the Sunburst malware"
        references = "https://www.mandiant.com/resources/blog/
        evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburs
        www.mandiant.com/resources/blog/sunburst-additional-technical-details | htt
        mandiant/sunburst_countermeasures/tree/main/rules/SUNBURST/yara"
        sha256 = "019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134"
    strings:
    condition:
}