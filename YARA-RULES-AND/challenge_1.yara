import "pe"
import "hash"
import "console"
private rule x { condition: 1 }
rule calculateCRC32OfTextSection {
    meta:
        description = "Calculate the CRC32 of the .text section of a PE file"
    condition:
        console.log("Section_Name: ",pe.sections[0].name) and
        console.log("crc32_checksum - ",hash.crc32(512, 8704))
}
/*
        sections
                [0]
                        name = ".text"
                        full_name = ".text"
                        characteristics = 1610612768
                        virtual_address = 8192
                        virtual_size = 8216
                        raw_data_offset = 512
                        raw_data_size = 8704
                        pointer_to_relocations = 0
                        pointer_to_line_numbers = 0
                        number_of_relocations = 0
                        number_of_line_numbers = 0





private rule renamed_powershell {
    meta:
        author = "gavink"
        description = "rule to detect renamed powershell binary that is not present in C:\\Windows\\system32"
    condition:
        pe.version_info["InternalName"] contains "powershell" 
        and not ext_path contains "C:\\Windows\\System32"
}

