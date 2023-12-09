import "pe"
import "console"
rule Patchwork_Sample_Strings_1 {
    meta:
        hash = "3d3598d32a75fd80c9ba965f000639024e4ea1363188f44c5d3d6d6718aaa1a3"
        ref = "https://www.malwarebytes.com/blog/threat-intelligence/2022/01/patchwork-apt-caught-in-its-own-web"
    strings:
        $a01 = "jlitest.dll"
        $a02 = "JLI_AcceptableRelease"
        $a03 = "JLI_ExactVersionId"
        $a04 = "JLI_FreeManifest"
        $a05 = "JLI_JarUnpackFile"
        $a06 = "JLI_Launch"
        $a07 = "JLI_ManifestIterate"
        $a08 = "JLI_MemAlloc"
        $a09 = " JLI_MemFree"
        $a010 = " JLI_MemRealloc"
        $a011 = "JLI_ParseManifest"
        $a012 = "JLI_PrefixVersionId"
        $a013 = " JLI_StringDup"
        $a014 = "JLI_ValidVersionString"
        $a015 = "JLI_WildcardExpandClasspath"
        $pdb = "E:\\new_ops\\jlitest __change_ops -29no - Copy\\Release\\jlitest.pdb"
    condition:
        uint16be(0) == 0x4d5a and
        5 of ($a*) or $pdb
}

rule Patchwork_Sample_PE_Features_1 {
    meta:
        hash = "3d3598d32a75fd80c9ba965f000639024e4ea1363188f44c5d3d6d6718aaa1a3"
        ref = "https://www.malwarebytes.com/blog/threat-intelligence/2022/01/patchwork-apt-caught-in-its-own-web"
    condition:
        (pe.number_of_signatures == 0 and pe.dll_name == "jlitest.dll")

        or

        (pe.timestamp == 1639036360 and pe.export_timestamp == 4294967295)

        or

        (for 3 func in pe.export_details:
        (
            func.name startswith "JLI_"
        )
        and pe.pdb_path contains "E:\\new_ops\\jlitest")
}

rule Patchwork_Sample_Network_Strings_1 {
    meta:
        hash = "3d3598d32a75fd80c9ba965f000639024e4ea1363188f44c5d3d6d6718aaa1a3"
        ref = "https://www.malwarebytes.com/blog/threat-intelligence/2022/01/patchwork-apt-caught-in-its-own-web"
    strings:
        $hifi1 = "Gfg786v6fcd6v8j09jg67f6" //Gfg786v6fcd6v8j09jg67f6/revshll.php
        $hifi2 = "bgre.kozow.com"
        $b1 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.10) Gecko/2009042316 Firefox/3.0.10"
        $b2 = "Content-Type: application/x-www-form-urlencoded"
        $a2 = "uuid=%s&response=%s"
        $a3 = "uuid=%s&user=%s&atcomp=%s&os=%s"
        $a4 = "uuid="
        $a5 = "fname="
        $a6 = "&fcat="
        $a7 = "&fdata"
        $w = "URLDownloadToFileA"
    condition:
        uint16be(0) == 0x4d5a and
        (1 of ($hifi*) or 3 of ($a*)) and (1 of ($b*) and $w)
}   

rule Patchwork_Sample_Logging_Strings_1 {
    meta:
        hash = "3d3598d32a75fd80c9ba965f000639024e4ea1363188f44c5d3d6d6718aaa1a3"
        ref = "https://www.malwarebytes.com/blog/threat-intelligence/2022/01/patchwork-apt-caught-in-its-own-web"
    strings:
        $a1 = "Result matrix is"
        $a2 = "CoInitializeEx failed: %x"
        $a3 = "CoInitializeSecurity failed: %x"
        $a4 = "Failed to create an instance of ITaskService: %x"
        $a5 = "ITaskService::Connect failed: %x"
        $a6 = "Cannot get Root Folder pointer: %x"
        $a7 = "%04hu-%02hu-%02huT%02hu:%02hu:%02huZ"
        $a8 = "asdf1234"
        $a9 = "Failed to open the file.File should be in current folder. Exiting......."
        $a10 = "Failed to create output file. Exiting......."
        $a11 = "Gfg786v6fcd6v8j09jg67f6/addentry2.php"
        $a12 = "Gfg786v6fcd6v8j09jg67f6/revshll.php"
        $a13 = "Gfg786v6fcd6v8j09jg67f6/filedownload2.php"
    condition:
        80% of them and pe.is_dll(S)
}