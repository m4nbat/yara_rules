rule ttp_base64_kernel32_dll 
{
    meta:
        author = "manb4t"
    strings:
        $a ="KERNEL32.DLL" base64 base64wide
        $b ="Kernel32.dll" base64 base64wide
        $c ="kernel32.dll" base64 base64wide
    condition:
        uint16be(0) == 0x4d5a
        and any of them
}
rule ttp_casing_nonstd_kernel32_dll 
{
    strings:
        $a = "kernel32.dll" nocase
        $z1 = "KERNEL32.DLL"
        $z1 = "kernel32.dll"
        $z1 = "Kernel32.dll"
        $z1 = "KERNEL32.dll"
    condition:
        $a and not any of ($z*)
}
rule mal_badstringo_str 
{
    strings:
        $plain = "badstringo" nocase ascii wide
        $b64_1 = "BADSTRINGO" base64 base64wide
        $b64_2 = "badstringo" base64 base64wide
        $b64_3 = "BadStringO" base64 base64wide
        $xor_1 = "badstringo"
        $xor_2 = "BADSTRINGO"
        $xor_3 = "BadStringO"
        $reverse = "0gnirtsdab"
        $rot13 = "onqfgevatb"
    condition:
        uint16be(0) == 0x4d5a
        and any of them
}
