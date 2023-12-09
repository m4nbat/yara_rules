rule MAL_CobaltStrike_StartW {
strings:
$a = "StartW" 
$b1 = "beacon.dll"  fullword        
$b2 = "beacon.x86.dll" fullword        
$b3 = "beacon.x64.dll" fullword
$z = "rule MAL_CobaltStrike"
condition:
filesize < 5MB and $a and 1 of ($b*) and not $z
}