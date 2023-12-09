import "pe"
import "hash"
import "console"
rule apt_turla_uroboros_exports_hifi {
    meta:
        sha256 = "d597e4a61d94180044dfb616701e5e539f27eeecfae827fb024c114e30c54914"
    condition: 
        pe.export_timestamp == 1359984004
        and pe.number_of_exports > 30
        and pe.dll_name == "inj_snake_Win32.dll"
}
import "pe"
import "hash"
import "console"
rule apt_turla_uroboros_exports_lofi {
    meta:
        sha256 = "d597e4a61d94180044dfb616701e5e539f27eeecfae827fb024c114e30c54914"
    condition: 
        true
}
rule turla_uroboros_exports_hifi_alt {
	meta:
		md5 = "a762d2c56999eda5316d0f94aba940cb"
		sha256 = "d597e4a61d94180044dfb616701e5e539f27eeecfae827fb024c114e30c54914"
	condition:
		pe.number_of_exports != 0
		and
		for 2 thing in pe.export_details:
			(
			thing.name startswith "snake_"
			)
		and
		for 40 thing in pe.export_details:
			(
			thing.name matches /^[a-z]{2}_/
			)
}
rule TTP_Export_Number_Unsigned_High_Exports_Timestamp_Oddity {
	meta:
		desc = "Anomaly rule looking for PEs with a large number of exported functions"
	condition:
		pe.number_of_signatures == 0
		and
		pe.number_of_exports > 60
		and
		pe.timestamp < pe.export_timestamp
		and
		filesize < 1MB
}

/*
timestamp = 1359984004
export_timestamp = 1359984004
dll_name = "inj_snake_Win32.dll"
number_of_exports = 61
name = "snake_alloc"
name = "snake_free"
name = "snake_log"
name = "snake_modules_command"
number_of_exports = 61
*/