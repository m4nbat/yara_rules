rule mal_bunnyloader_strings1 {
    meta:
        description = "bunnyloader"
        author = "Gavin Knapp - Bridewell CTI"
        date = "2023-10-06"
        hash1 = "90e6ebc879283382d8b62679351ee7e1aaf7e79c23dd1e462e840838feaa5e69"
    strings:
        $x1 = "C:\\Users\\user\\Desktop\\Bunny\\Bunny\\Release\\Bunny.pdb" ascii
        $x2 = "C:\\Users\\user\\Downloads\\cryptopp870\\sse_simd.cpp" ascii
        $x3 = "C:\\Users\\user\\Downloads\\cryptopp870\\rijndael_simd.cpp" ascii
        $x4 = "C:\\Users\\user\\Downloads\\cryptopp870\\gf2n_simd.cpp" ascii
        $x5 = "C:\\Users\\user\\Downloads\\cryptopp870\\sha_simd.cpp" ascii
        $s1 = "C:\\Users\\user\\Downloads\\cryptopp870\\gcm_simd.cpp" ascii
        $s2 = "powershell -Command \"Add-Type -A 'System.IO.Compression.FileSystem'; [System.IO.Compression.ZipFile]::CreateFromDirectory('" ascii
        $s3 = "\\AppData\\Local\\BunnyLogs\\Browser\\Downloads.txt" ascii
        $s4 = "\\AppData\\Local\\BunnyLogs\\Browser\\Passwords.txt" ascii
        $s5 = "cmdvrt32.dll" ascii
        $s6 = "\\AppData\\Local\\BunnyLogs\\Keystrokes.txt" ascii
        $s7 = "\\AppData\\Local\\BunnyLogs\\Information.txt" ascii
        $s8 = "\\AppData\\Local\\BunnyLogs\\Browser\\CCs.txt" ascii
        $r1 = "/Bunny/TaskHandler.php?CommandID=" ascii
        $r2 = "/Bunny/Echoer.php" ascii
        $r3 = "/Bunny/Heartbeat.php" ascii
        $r4 = "/Bunny/TaskHandler.php" ascii
    condition:
        uint16be(0) == 0x4d5a and all of ($x*) and 4 of ($r*) and 5 of ($s*)
}

rule mal_bunnyloader_strings2 {
    meta:
        description = "bunnyloader_strings"
        author = "Gavin Knapp - Bridewell CTI"
        date = "2023-10-06"
        hash1 = "90e6ebc879283382d8b62679351ee7e1aaf7e79c23dd1e462e840838feaa5e69"
    strings:
        $x1 = "C:\\Users\\user\\Desktop\\Bunny\\Bunny\\Release\\Bunny.pdb" ascii
        $x2 = "C:\\Users\\user\\Downloads\\cryptopp870\\sse_simd.cpp" ascii
        $x3 = "C:\\Users\\user\\Downloads\\cryptopp870\\rijndael_simd.cpp" ascii
        $x4 = "C:\\Users\\user\\Downloads\\cryptopp870\\gf2n_simd.cpp" ascii
        $x5 = "C:\\Users\\user\\Downloads\\cryptopp870\\sha_simd.cpp" ascii
        $s1 = "C:\\Users\\user\\Downloads\\cryptopp870\\gcm_simd.cpp" ascii
        $s2 = "powershell -Command \"Add-Type -A 'System.IO.Compression.FileSystem'; [System.IO.Compression.ZipFile]::CreateFromDirectory('" ascii
        $s3 = "\\AppData\\Local\\BunnyLogs\\Browser\\Downloads.txt" ascii
        $s4 = "\\AppData\\Local\\BunnyLogs\\Browser\\Passwords.txt" ascii
        $s6 = "\\AppData\\Local\\BunnyLogs\\Keystrokes.txt" ascii
        $s7 = "\\AppData\\Local\\BunnyLogs\\Information.txt" ascii
        $s8 = "\\AppData\\Local\\BunnyLogs\\Browser\\CCs.txt" ascii
        $r1 = "/Bunny/TaskHandler.php?CommandID=" ascii
        $r2 = "/Bunny/Echoer.php" ascii
        $r3 = "/Bunny/Heartbeat.php" ascii
        $r4 = "/Bunny/TaskHandler.php" ascii
    condition:
        uint16be(0) == 0x4d5a and 3 of ($x*) and 4 of ($r*) and 5 of ($s*)
}