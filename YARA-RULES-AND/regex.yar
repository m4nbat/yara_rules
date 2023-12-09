rule Regex_VBS_PAths {
    meta:
        author = "gknapp"
        description = "desc"
        sha256 = ""
    strings:
        $r1 = /[a-z]:\\[^\x00]{5,200}\.vbs\x00/ nocase
    condition:
        $r1
}