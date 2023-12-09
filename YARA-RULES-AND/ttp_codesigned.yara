import "console"
import "pe"
rule ttp_codesigned_01 {
    meta:
        sha256 = "78a07502443145d762536afaabd4d6139b81ca3cc9f8c28427ec724a3107e17b,f1cbacea1c6d05cd5aa6fc9532f5ead67220d15008db9fa29afaaf134645e9de"
        author = "manb4t"
    condition:
        pe.number_of_signatures > 0

}
rule ttp_codesigned_02 {
    meta:
        sha256 = "78a07502443145d762536afaabd4d6139b81ca3cc9f8c28427ec724a3107e17b,f1cbacea1c6d05cd5aa6fc9532f5ead67220d15008db9fa29afaaf134645e9de"
        author = "manb4t"
    condition:
        pe.number_of_signatures > 0
        and
        for any thing in pe.signatures:
        (
            thing.issuer == "/CN=Google Inc"
            or thing.issuer == "/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services CA - G2"
            or thing.issuer == "/C=ZA/ST=Western Cape/L=Durbanville/O=Thawte/OU=Thawte Certification/CN=Thawte Timestamping CA"
        ) 
}
rule Code_Sig_42_6e_86_or_2e_3c_dd {
    meta:
        desc = "Code signing cert used to sign at least one piece of malware."
        ref = "78a07502443145d762536afaabd4d6139b81ca3cc9f8c28427ec724a3107e17b"
    condition:
        pe.number_of_signatures > 0
        and 
        for any thing in pe.signatures:
        (
            thing.serial == "42:6e:86:60:53:09:73:ac:4e:fd:3b:0d:41:f1:c6:1f"
            or thing.serial == "2e:3c:dd:64:c2:66:e1:9e:47:99:56:52:fe:0c:79:a2"
        )
}
rule Mal_Cert_GoogleInc {
    condition:
        for any thing in pe.signatures:
        (
            thing.issuer == "/CN=Google Inc"
            and
            thing.subject == "/CN=Google Inc"
        )
}

rule TTP_CodeSigned_Same_Issuer_Subject {
    meta:
        description = "Looking for oddity where certificate issuer is the exact same as the subject"
    condition:
        for any thing in pe.signatures:
        (
            thing.issuer == thing.subject 
            and console.log("Issuer: ",thing.issuer)
            and console.log("Subject: ",thing.subject)
        )
}
rule TTP_CodeSign_Short_Issuer {
    condition:
    for any thing in pe.signatures:
    (
        thing.issuer matches /^[a-zA-Z0-9\.\_=\/\s]{1,8}$/
        and console.log("Issuer: ",thing.issuer)
    )
}


/*
        pe.signatures.issuer == "/CN=Google Inc"
        == "/C=US/O=Symantec Corporation/CN=Symantec Time Stamping Services CA - G2"
        == "/C=ZA/ST=Western Cape/L=Durbanville/O=Thawte/OU=Thawte Certification/CN=Thawte Timestamping CA"
*/