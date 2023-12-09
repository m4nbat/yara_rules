import "pe"
import "console"
rule MAL_HOUSEOFCARDS_Str_Ascii {
	meta:
		author = "smiller"
		desc = "This is an example of a *bad* rule. If this is encoded or obfuscated data, another sample of the malware might have none of these, if just because the encoding began at another offset."
		ref = "fb2fbca3be381bb1a0b410f66e04f114"
	strings:
		$a = "iuugxvyzyc"
		$b = "rmzrducaya"
		$c = "nxmwxxvouo"
		$d = "wprhdxzotl"
		$f = "ghvriwepti"
	condition:
		uint16be(0) == 0x4d5a
		and all of them
}
rule MAL_HOUSEOFCARDS_Str_Wide {
	meta:
		author = "smiller"
		desc = "UTF wide strings extracted by FLOSS"
		ref = "fb2fbca3be381bb1a0b410f66e04f114"
	strings:
		$a = "ixploer.exe" wide
		$b = "90f69f910972360b7378edb22b4e4cca" wide
		//$c = "basharalassad1.no-ip.biz"
		$d = "U0VFX01BU0tfTk9aT05FQ0hFQ0tT" wide//SEE_MASK_NOZONECHECKS
		$f = "cmd.exe /k ping 0 & del \"" wide
	condition:
		uint16be(0) == 0x4d5a
		and 3 of them
}
rule MAL_HOUSEOFCARDS_Dotnet {
	meta:
		author = "smiller"
		desc = "Dotnet features from dotnet module"
		ref = "fb2fbca3be381bb1a0b410f66e04f114"
	condition:
		for any guid in dotnet.guids:
		(
			guid == "276a7b08-53ff-4e50-9d92-8f261c83d0dc"
		)
}
rule MAL_HOUSEOFCARDS_Stack_Str {
	meta:
		author = "smiller"
		ref = "fb2fbca3be381bb1a0b410f66e04f114"
	strings:
		$a = /\x1fM[\x01-\xff]{2}\x1f[\x01-\xff]{1}\x1fi[\x01-\xff]{2}\x1f[\x01-\xff]{1}\x1fc[\x01-\xff]{2}\x1f[\x01-\xff]{1}\x1fr[\x01-\xff]{2}\x1f[\x01-\xff]{1}\x1fo[\x01-\xff]{2}\x1f[\x01-\xff]{1}\x1fs[\x01-\xff]{2}\x1f[\x01-\xff]{1}\x1fo[\x01-\xff]{2}\x1f[\x01-\xff]{1}\x1ff[\x01-\xff]{2}\x1f[\x01-\xff]{1}\x1ft/
	condition:
		uint16be(0) == 0x4d5a
		and $a
}
rule TTP_1f_Str_Type {
	meta:
		author = "smiller"
		ref = "fb2fbca3be381bb1a0b410f66e04f114"
	strings:
		$a = /\x1f[\x01-\x7f]{1}[\x01-\xff]{2}\x1f[\x01-\xff]{1}\x1f/
	condition:
		uint16be(0) == 0x4d5a
		and #a > 20
}
rule MAL_IXESHE_Str {
	meta:
		author = "smiller"
		md5_hash = "80dad66d6224d18babd9ada4a26aee75"
	strings:
		$a = "Process Do not exit in 10 second, so i Kill it!"
		$b = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; GTB6; .NET CLR 1.1.4322; .NET C" wide
		$c = "LR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648)" wide
		$d = "www.google.com.tw" wide
		$e = {73 70 6F 6F 6C 73 76 00 3F 3F 3F 00 4F 4B 00} //spoolsv ??? OK
	condition:
		3 of them
}
rule MAL_IXESHE_Stack_Str {
	meta:
		author = "smiller"
		md5_hash = "80dad66d6224d18babd9ada4a26aee75"
	strings:
		//$a = {c6 85 [5] c6 85}
		// 7 byte pattern
		//HKEY_CURRENT_USER 
		$r = /\xc6\x85[\x01-\xff]{4}H\xc6\x85[\x01-\xff]{4}K\xc6\x85[\x01-\xff]{4}E\xc6\x85[\x01-\xff]{4}Y\xc6\x85[\x01-\xff]{4}_\xc6\x85[\x01-\xff]{4}C\xc6\x85[\x01-\xff]{4}U\xc6\x85[\x01-\xff]{4}R\xc6\x85[\x01-\xff]{4}R\xc6\x85[\x01-\xff]{4}E\xc6\x85[\x01-\xff]{4}N\xc6\x85[\x01-\xff]{4}T\xc6\x85[\x01-\xff]{4}_\xc6\x85[\x01-\xff]{4}U\xc6\x85[\x01-\xff]{4}S\xc6\x85[\x01-\xff]{4}E\xc6\x85[\x01-\xff]{4}R/
	condition:
		any of them
}
rule TTP_Stack_SevenBytePattern {
	meta:
		author = "smiller"
		md5_hash = "80dad66d6224d18babd9ada4a26aee75"
	strings:
		//$a = {c6 85 [5] c6 85}
		// 7 byte pattern
		$r = /\xc6\x85[\x01-\xff]{4}[\x01-\x7f]{1}\xc6\x85/
	condition:
		#r > 50
		and pe.number_of_signatures == 0
}
rule MAL_HIGAISA_Str {
	meta:
		author = "smiller"
		md5_hash = "50c86f1de6caeefce7c1d7e2ef39aa79"
	strings:
		$a1 = "pys.jpg"
		$a2 = "happy.txt"
		$b1 = "WOW64; _OLE2BIND Trident/4.0; 18A0918C SV1)"
		$b2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1;"
		$c1 = "&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz"
		$c2 = "%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz"
	condition:
		uint16be(0) == 0x4d5a
		and 1 of ($a*) and 2 of ($b*) and 1 of ($c*)
}
rule MAL_HIGAISA_Stack_Str_ABCDE012345678 {
	meta:
		author = "smiller"
	strings:
		//1725h: C6 44 24 41 65 C6 44 24 42 74 C6 44 24 43 65 C6 ÆD$AeÆD$BtÆD$CeÆ 
		//1735h: 44 24 44 72 C6 44 24 45 73 88 5C 24 46 C6 44 24 D$DrÆD$Esˆ\$FÆD$ 
		//1745h: 30 53 C6 44 24 31 45 C6 44 24 32 52 C6 44 24 33 0SÆD$1EÆD$2RÆD$3 
		//1755h: 56 C6 44 24 34 49 C6 44 24 35 43 C6 44 24 36 65 VÆD$4IÆD$5CÆD$6e 
		//1765h: C6 44 24 37 ÆD$7
		$a = {c6 44 ?? 41 ?? c6 44 ?? 42 ?? c6 44 ?? 43 ?? c6 44 ?? 44 ?? c6 44 ?? 45 ??}
		$b = {c6 44 ?? 31 ?? c6 44 ?? 32 ?? c6 44 ?? 33 ?? c6 44 ?? 34 ?? c6 44 ?? 35 ??}
	condition:
		uint16be(0) == 0x4d5a
		and all of them
}
rule TTP_Stack_Str_FiveBytePattern {
	meta:
		author = "smiller"
	strings:
		//1725h: C6 44 24 41 65 C6 44 24 42 74 C6 44 24 43 65 C6 ÆD$AeÆD$BtÆD$CeÆ 
		$a = {c6 44 [3] c6 44 [3] c6 44 [3] c6 44 }
		//1C62h: C6 84 24 27 01 00 00 4D C6 84 24 28 01 00 00 6F Æ„$'...MÆ„$(...o 
		$b = {c6 84 [3] c6 84 [3] c6 84 [3] c6 84 }
	condition:
		uint16be(0) == 0x4d5a
		and #a + #b > 10
}
rule MAL_KEYBOY_Str {
	meta:
		author = "smiller"
		ref = "5708e0320879de6f9ac928046b1e4f4e"
	strings:
		$a = "Internet using \\svchost.exe -k -n 3"
		$b = "start stop service:%s"
		$c = "sc create %s binpath= \"%s\" Type= share Start= auto DisplayName= \"%s\""
		$d = "reg add HKLM\\%s\\Parameters /v ServiceDll /t REG_EXPAND_SZ /d \"%s\" /f"
		$e = "Current user is a member of the %s\\%s group"
		$f = "ChangeFileTime %s->%s"
	condition:
		uint16be(0) == 0x4d5a
		and 5 of them
}
rule MAL_KEYBOY_Stack_Str {
	meta:
		author = "smiller"
		ref = "5708e0320879de6f9ac928046b1e4f4e"
	strings:
		//0990h: 53 FF 15 7C 56 02 10 C7 45 EC 50 72 6F 67 8B CB Sÿ.|V..ÇEìProg‹Ë 
		//09A0h: C7 45 F0 72 61 6D 44 C7 45 F4 61 74 61 00 8A 44 ÇEðramDÇEôata.ŠD 
		$s = {c7 45 ?? 50 72 6F 67 ?? ?? c7 45 ?? 72 61 6D 44 c7 45 ?? 61 74 61 00}
	condition:
		any of them
}
rule TTP_Stack_Str_NineBytePattern {
	meta:
		author = "smiller"
		desc = "Stack string pattern, for four byte chunks."
	strings:
		$s = {c7(44|45)?? ?? ?? ?? ?? c7(44|45)}
	condition:
		uint16be(0) == 0x4d5a
		and #s > 20
}

rule mal_stack_strings {
    meta:
        author = "manb4t"
    strings:
        $hex1 = { c6 44 24 ?? 4d }
        $regex = /\xc6\x44\x24.\x4d/
        $hex2 = { c6 45 ?? ?? c6 45 }
    condition:
        ($hex1 or $regex) or $hex2
}
rule mal_higaisa_stack_strings {
    meta:
        author = "manb4t"
        hash = "50c86f1de6caeefce7c1d7e2ef39aa79"
    strings:
        $s1 = "WOW64; _OLE2BIND Trident/4.0; 18A0918C SV1)" ascii
        $s2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1;" ascii
        $s3 = "$29375C8E-6D3A-4CE8-9024-FE5533560720" ascii
        $s4 = "id='W5M0MpCehiHzreSzNTczkc9d'" ascii
        $s5 = "Happy Mid-Autumn Festival!" ascii
        $s6 = "Masuzo Asano" ascii
        $su1 = "Project Peakul Accessorial" wide
        $su2 = "nana.exe" wide
        $su3 = "Hello World!" wide
        $su4 = "Masuzo Asano" wide
        $hex = { c6 44 24 ?? 4d }
    condition:
        75% of ($s*) and 75% of ($su*) and $hex
}
rule mal_keyboy_stack_strings {
    meta:
        author = "manb4t"
        hash = "5708e0320879de6f9ac928046b1e4f4e"
    strings:
        $s1 = "deflate 1.2.3 Copyright" ascii 
        $s2 = "sc create %s binpath= \"%s\" Type= share Start= auto DisplayName= \"%s\"" ascii
        $s3 = "reg add HKLM\\%s\\Parameters /v ServiceDll /t REG_EXPAND_SZ /d \"%s\" /f" ascii
        $s4 = "Current user is a member of the %s\\%s group" ascii
        $s5 = "Internet using \\svchost.exe -k  -n 3" ascii
        $s6 = "Ping 127.0.0.1" ascii
        $s7 = "%s\\cmd.exe /c \"%s\"" ascii
        $hex = { c6 45 ?? ?? c6 45 }
    condition:
        80% of ($s*) and $hex
}

/*
higaisa
ascii:

 WOW64; _OLE2BIND Trident/4.0; 18A0918C SV1)
Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1;
Masuzo Asano
$29375C8E-6D3A-4CE8-9024-FE5533560720

2018:09:18 21:09:50
2018:09:18 21:09:50


<?xpacket begin='
' id='W5M0MpCehiHzreSzNTczkc9d'?>
<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b" xmlns:dc="http://purl.org/dc/elements/1.1/"/><rdf:Description rdf:about="uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b" xmlns:xmp="http://ns.adobe.com/xap/1.0/"><xmp:CreateDate>2018-09-18T21:09:50.729</xmp:CreateDate></rdf:Description><rdf:Description rdf:about="uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator><rdf:Seq xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:li>plus00</rdf:li></rdf:Seq>
                        </dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>


Happy Mid-Autumn Festival!

unicode:

Project Peakul Accessorial
Copyright (C) 2003-2017 OJN. Corporation.
nana.exe
Hello World!
Hellp
Masuzo Asano

keyboy:

deflate 1.2.3 Copyright 1995-2005 Jean-loup Gailly 

sc create %s binpath= "%s" Type= share Start= auto DisplayName= "%s"
reg add HKLM\%s\Parameters /v ServiceDll /t REG_EXPAND_SZ /d "%s" /f
%s\cmd.exe /c "%s"
Current user is a member of the %s\%s group
Internet using \svchost.exe -k  -n 3
Ping 127.0.0.1


/