rule MZ_Std_PE {
    condition:#
    uint16be(0) == 0x4D51
    and
    unint32(unit32(0x3c)) == 0x00004550
}