import "pe"
import "console"
rule MustangPanda_Downloader_Regex {
    meta:
        hash = "1b520e4dea36830a94a0c4ff92568ff8a9f2fbe70a7cedc79e01cea5ba0145b0"
        ref = "https://blog.talosintelligence.com/mustang-panda-targets-europe/" 
    strings:
        //$reg1 = /?i^https:\/\/[1-9]{1,3}\.[0-9]{1,3}\.[1-9]{1,3}\.[1-9]{1,3}\/2022\/PotPlayer\.exe\// wide nocase
        //$reg2 = /?i^https:\/\/[1-9]{1,3}\.[0-9]{1,3}\.[1-9]{1,3}\.[1-9]{1,3}\/2022\/PotPlayer\.dll\// wide nocase
        //$reg3 = /?i^https:\/\/[1-9]{1,3}\.[0-9]{1,3}\.[1-9]{1,3}\.[1-9]{1,3}\/2022\/PotPlayerDB\.dat\// wide nocase
        $reg = /https:\/\/[1-9]{1,3}\.[0-9]{1,3}\.[1-9]{1,3}\.[1-9]{1,3}\/2022\/(PotPlayer|PotPlayerDB)\.(exe|dat|dll)/ wide nocase
    condition:
        all of ($reg*)
}

rule MustangPanda__Downloader_Strings1 {
    meta:
        hash = "1b520e4dea36830a94a0c4ff92568ff8a9f2fbe70a7cedc79e01cea5ba0145b0"
        ref = "https://blog.talosintelligence.com/mustang-panda-targets-europe/" 
    strings:
         $s1 = "https://45.154.14.235/2022/COVID-19 travel restrictions EU reviews list of third countries.doc" wide
         $s2 = "/c ping 8.8.8.8 -n 70&&\"%temp%\\PotPlayer.exe" wide
         $s3 = "https://45.154.14.235/2022/PotPlayer.exe" wide
         $s4 = "https://45.154.14.235/2022/PotPlayer.dll" wide
         $s5 = "https://45.154.14.235/2022/PotPlayerDB.dat" wide
    condition:
        4 of ($s*)
}

rule MustangPanda_Downloader_Strings2 {
    meta:
        hash = "1b520e4dea36830a94a0c4ff92568ff8a9f2fbe70a7cedc79e01cea5ba0145b0"
        ref = "https://blog.talosintelligence.com/mustang-panda-targets-europe/" 
    strings:
         $s1 = "45.154.14.235" wide
         $s2 = "/c ping 8.8.8.8 -n" wide
         $s3 = "PotPlayer.exe" wide
         $s4 = "PotPlayer.dll" wide
         $s5 = "PotPlayerDB.dat" wide
    condition:
        uint16be(0) == 0x4d5a and // MZ header
        4 of ($s*)
}

import "pe"
rule Unknown_rule {
	meta:
		desc = "PE features from Mustang Panda downloader, which may lead to PlugX malware"
		hash = "1b520e4dea36830a94a0c4ff92568ff8a9f2fbe70a7cedc79e01cea5ba0145b0"
	condition:
		pe.number_of_signatures == 0 and
		pe.number_of_resources > 20
}

import "pe"
rule MustangPanda_Downloader_Broad_Strings {
	meta:
		desc = "Strings from Mustang Panda downloader, which may lead to PlugX malware"
		hash = "1b520e4dea36830a94a0c4ff92568ff8a9f2fbe70a7cedc79e01cea5ba0145b0"
	strings:
		$a1 = "/c ping 8.8.8.8 -n" wide
		$a2 = "cmd.exe" wide
		$a3 = "https" wide
		$a4 = "200 ok" wide
		$a5 = "200 OK" wide
	condition:
		4 of them
}