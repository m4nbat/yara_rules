import "console"
import "hash"
import "pe"
rule is_a_dll {
    condition:
        pe.is_dll()
}

rule flipflop_pe_detail {
    condition:
        pe.is_dll() and 
        pe.number_of_resources == 1 and
        pe.number_of_signatures == 0
}

rule hash {
    condition:
        console.log("The SHA is:", 
        hash.sha256(0,filesize))
}