import "pe"
rule ttp_masquerading_svchost_pdb_path_not_svchost {
    meta:
        author = "manb4t"
    condition:
        pe.pdb_path != "svchost.pdb" and
        pe.characteristics > 100
}   
rule TTP_VersionInfo_Svchost_Has_C_Users_String {
	meta:
		desc = "Anything with svchost in the VersionInfo with C:\\Users path"
		ref = "D723B7C150427A83D8A08DC613F68675690FA0F5B10287B078F7E8D50D1A363F"
	strings:
		$s = "C:\\Users\\"
	condition:
		(
			pe.version_info["InternalName"] icontains "svchost" or
			pe.version_info["OriginalFilename"] icontains "svchost"
		)
	and $s
}
rule TTP_VersionInfo_Svchost_Manifest_Mismatch {
	meta:
		desc = "Anything with svchost in the VersionInfo"
		ref = "D723B7C150427A83D8A08DC613F68675690FA0F5B10287B078F7E8D50D1A363F"
	strings:
		$a1 = "<!-- Copyright (c) Microsoft Corporation -->"
		$a2 = "name=\"Microsoft.Windows.Services.SvcHost\""
		$a3 = "<description>Host Process for Windows Services</description>"
	condition:
		(
			pe.version_info["InternalName"] icontains "svchost" or
			pe.version_info["OriginalFilename"] icontains "svchost"
		)
		and not any of ($a*)
}
rule TTP_VersionInfo_Svchost_Giant_Filesize {
	meta:
		desc = "Anything with svchost in the VersionInfo"
		ref = "D723B7C150427A83D8A08DC613F68675690FA0F5B10287B078F7E8D50D1A363F"
	condition:
		filesize > 2MB
		and (
			pe.version_info["InternalName"] icontains "svchost" or
			pe.version_info["OriginalFilename"] icontains "svchost"
			)
}
rule FerociousKitten_D723B7_Strings {
	meta:
		desc = "Unique strings from a sample of malware associated with the threat actor Ferocious Kitten."
		ref = "D723B7C150427A83D8A08DC613F68675690FA0F5B10287B078F7E8D50D1A363F"
	strings:
		$a0 = "bitsadmin /cancel pdj"
		$a1 = "bitsadmin /SetPriority pdj HIGH"
		$a2 = "bitsadmin /addfile pdj"
		$b1 = "i.php?u=&i=proxy ip"
		$b2 = "mklg-binder.pdb"
		$b3 = "\\mklg -binder\\Release"
		$b4 = "<mark>%s</mark>"
	condition:
		uint16be(0) == 0x4d5a and
		1 of ($a*) and 2 of ($b*)
}
rule mal_ferociouskitten_d723b7_strings_hifi {
    meta:
        author = "manb4t"
        sha256 = "D723B7C150427A83D8A08DC613F68675690FA0F5B10287B078F7E8D50D1A363F"
        desc = "Unique strings from a sample of malware associated with the threat actor Ferocious Kitten."
    strings:
        $h1 = "\\mklg -binder\\Release"
        $h2 = "mklg-binder.pdb"
        $h3 = "/i.php?u=&i=proxy ip"
        $h4 = "bitsadmin /cancel pdj"
        $h5 = "bitsadmin /create pdj"
        $h6 = "bitsadmin /SetPriority pdj HIGH"
        $h7 = "bitsadmin /addfile pdj"
        $h8 = "bitsadmin /resume pdj"
        $s9 = "<mark>Hello: %s</mark>"
        $s10 = "svehost.exe"
    condition:
        uint16be(0) == 0x4d5a and
        90% of them
}

/*
Content-Disposition: form-data; name="uploadedfile"; filename="
bitsadmin /cancel dd
bitsadmin /create dd
bitsadmin /SetPriority dd HIGH
bitsadmin /SetProxySettings dd NO_PROXY
bitsadmin /addfile dd "
\Software\Windows\
bitsadmin /resume dd
\jdr.nfo
bitsadmin /info dd > 
/up/upload.php?u=
bitsadmin /reset
bitsadmin /complete dd
\Software\Windows\svehost.exe
\mklg -binder\Release\mklg-binder.pdb
bitsadmin /cancel pdj
bitsadmin /create pdj
bitsadmin /SetPriority pdj HIGH
bitsadmin /addfile pdj "http://microsoft.updatei.com/i.php?u=
&i=proxy ip
\Software\Libs\p.b
bitsadmin /resume pdj
<mark>Hello: %s</mark>
/