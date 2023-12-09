import "console"
rule last_4_bytes_uint32 {
    condition:
        console.log(uint32(filesize -4))
}
