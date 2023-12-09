import "pe"
import "console"
rule TTP_xor_shellcode_1 {
strings:
	$s = "shellcode" xor(0x01-0xff)
condition:
	$s
}
rule TTP_xor_shellcode_2_hifi {
    strings:	
        $s = "shellcode" xor(0x01-0xff)
    condition:
        pe.pdb_path != "mrt.pdb" and
        pe.version_info ["CompanyName"] != "Microsoft Corporation"
        and pe.version_info ["InternalName"] != "mrt.exe"
        and pe.version_info ["LegalCopyright"] != "\\xa9 Microsoft Corporation. Reservados todos los derechos."
        and pe.version_info ["OriginalFilename"] != "Microsoft Corporation"
	    and $s
        and #s < 20
}
rule TTP_xor_shellcode_2_hifi_better {
    strings:	
        $s = "shellcode" xor(0x01-0xff)
    condition:
        uint16be(0) == 0x4d5a // anchor to PE MZ header
        and filesize < 10MB
        pe.pdb_path != "mrt.pdb" and
        pe.version_info ["CompanyName"] != "Microsoft Corporation"
        and pe.version_info ["InternalName"] != "mrt.exe"
        and pe.version_info ["LegalCopyright"] != "\\xa9 Microsoft Corporation. Reservados todos los derechos."
        and pe.version_info ["OriginalFilename"] != "Microsoft Corporation"
	and $s < 20
}
import "pe"
rule TTP_xor_shellcode_hifi {
strings:
	$s = "shellcode" xor(0x01-0xff)
condition:
	uint16be(0) == 0x4d5a // anchor to PE MZ header
    and filesize < 10MB 
    and pe.number_of_signatures == 0
    and pe.pdb_path != "mrt.pdb" //pdb_path = "mrt.pdb"
    and $s
    and #s < 20
}
rule TTP_xor_shellcode_lowfi {
strings:
	$s = "shellcode" xor(0x01-0xff)
condition:
	uint16be(0) == 0x4d5a // anchor to PE MZ header
    and filesize < 10MB 
    and pe.pdb_path != "mrt.pdb" //pdb_path = "mrt.pdb"
    and $s
}