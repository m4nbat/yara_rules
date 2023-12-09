import "math"
import "pe"
import "console"

rule mal_operation_groundbait_strings1 {
    meta:
        author = "manb4t"
        sha256 = "2639a62b2ab8ac81ad5f644837da3a900c592d650617b8fe74cb87585383ac6c"
        desc = "strings rule associated with malware used in the campaign operation groundbait - a Russian surveilance campaign leveraging the Prikormka malware family "
    strings:
        $ua = "User-agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)"
        $pdb1 = "samlib.pdb"
        $pdb2 = "\\samlib\\Release"
        $pdb3 = "D:\\Install\\P r o g r a m m i n g\\21.02.2011\\x32\\"
        $evade = "IsDebuggerPresent"
        $x1 = ".?AVtype_info@@"
        $x2 = ".?AVbad_alloc@std@@"
        $x3 = ".?AVexception@std@@"
        $y1 = "POST http://"
        $y2 = "GET http://"
        $y3 = "[EndPoint]"
    condition:
        all of them
}
rule mal_operation_groundbait_strings2 {
    meta:
        author = "manb4t"
        sha256 = "2639a62b2ab8ac81ad5f644837da3a900c592d650617b8fe74cb87585383ac6c"
        desc = "strings rule associated with malware used in the campaign operation groundbait - a Russian surveilance campaign leveraging the Prikormka malware family "
    strings:
        $persist = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $pdb1 = "samlib.pdb"
        $pdb2 = "\\samlib\\Release"
        $unicode1 = "disk-fulldatabase.rhcloud.com" wide ascii
        $unicode2 = "http://disk-fulldatabase.rhcloud.com/rmdir.php?action=del&folder=%s" wide ascii
        $unicode3 = "http://disk-fulldatabase.rhcloud.com/log.php?v=%s&f=%s&d=%s" wide ascii
        $unicode4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $y1 = "POST http://"
        $y2 = "GET http://"
        $y3 = "User-agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)"
    condition:
        $persist and
        1 of ($pdb*) and 
        1 of ($unicode*) and
        all of ($y*)
}

rule MAL_SOURSNACK_Strings {
	meta:
		author = "smiller"
		desc = "Strings from the SourSnack sample."
		ref = "f9ff42037f02b6a2eedf7a6fb7aedb4b5d1f0eb460069f4e923fb60b5ad0841a"
	strings:
		$a1 = "segelivirPdetseuqer" //backwards function
		$a2 = "WepyTgnirtSteG" // backwards functions
		$a3 = "ZYXWVUTSRQPONMLKJIHGFEDCBA"
		$b = "kwlods"
		$c = "widget.forum-pokemon.com"
	condition:
		uint16be(0) == 0x4d5a and
		(2 of ($a*) or #b > 20 or $c)
}
rule ttp_high_section_entropy_check_entropy {
	condition:
		for all section
        in pe.sections:
		(
			console.log("Section Entropy: ",math.entropy(section.raw_data_offset,section.raw_data_size))
            and
            console.log("Section name",section.name)
            and
            console.hex("Magic: ",uint16be(section.raw_data_offset))
		)
}
rule ttp_high_section_entropy {
	condition:
		for any section in pe.sections:
		(
			math.entropy(section.raw_data_offset,section.raw_data_size) >= 6.8
		)
}
rule ttp_high_resource_entropy_check {
	condition:
		for all resource
        in pe.resources:
		(
			console.log("Resource Entropy: ",math.entropy(resource.offset,resource.length))
            and
            console.log("Resource: ",resource.id)
            and
            console.hex("Magic: ",uint16be(resource.offset))
		)
}
rule ttp_high_resource_entropy {
	condition:
		for any resource in pe.resources:
		(
			math.entropy(resource.offset,resource.length) >= 7.5
		)
}



/*
Strings:

`vbase destructor'
`vector deleting destructor'
`default constructor closure'
`scalar deleting destructor'
`vector constructor iterator'
`vector destructor iterator'
`vector vbase constructor iterator'
`virtual displacement map'
`eh vector constructor iterator'
`eh vector destructor iterator'
`eh vector vbase constructor iterator'
`copy constructor closure'
`udt returning'
`local vftable'
`local vftable constructor closure'
 new[]
 delete[]
`omni callsig'
`placement delete closure'
`placement delete[] closure'
`managed vector constructor iterator'
`managed vector destructor iterator'
`eh vector copy constructor iterator'
`eh vector vbase copy constructor iterator'
`dynamic initializer for '
`dynamic atexit destructor for '
`vector copy constructor iterator'
`vector vbase copy constructor iterator'
`managed vector copy constructor iterator'

User-agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)
POST http://
GET http://
[EndPoint]

hauthuid.dll
WS2_32.dll

IsDebuggerPresent

.?AVtype_info@@
.?AVbad_alloc@std@@
.?AVexception@std@@

D:\Install\P r o g r a m m i n g\21.02.2011\x32\samlib\Release\samlib.pdb

</assembly>PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD

Unicode 16

disk-fulldatabase.rhcloud.com
http://disk-fulldatabase.rhcloud.com/rmdir.php?action=del&folder=%s
http://disk-fulldatabase.rhcloud.com/log.php?v=%s&f=%s&d=%s
Software\Microsoft\Windows\CurrentVersion\Run








2639a62b2ab8ac81ad5f644837da3a900c592d650617b8fe74cb87585383ac6c
Malware from Operation Groundbait: https://www.welivesecurity.com/wp-content/uploads/2016/05/Operation-Groundbait.pdf

f9ff42037f02b6a2eedf7a6fb7aedb4b5d1f0eb460069f4e923fb60b5ad0841a
SourSnack malware: https://cert.gov.ua/article/37246
/