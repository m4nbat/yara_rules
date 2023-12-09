rule position_0_5000 {
    strings: 
    $s = "asdfghjkl"
    condition:
    $s in (0..5000)
}
rule position_5000_to_eof {
    strings: 
    $s = "asdfghjkl"
    condition:
        $s in (5000..filesize)
}
rule position_not_in_first_or_last_5000 {
    strings: 
    $s = "asdfghjkl"
    condition:
        $s in (5000..(filesize-5000))
}
rule string_order_with_proximity {
    strings:
        $1st = "first"
        $2nd = "second"
        $3rd = "third"
    condition:
        @1st < @2nd
        and
        @2nd < @3rd
        and
        @3rd - @1st < 500
}
import "math"
rule string_order_with_proximity {
		meta:
				desc = "See Vitaly Kamluk's excellent blog about creative use of the math module to allow for ordering flexibility but still enforce proximity."
    strings:
        $1st = "first"
        $2nd = "second"
        $3rd = "third"
condition:
    @1st < @2nd 
    and
    @2nd < @3rd
    and
    @3rd - @1st < 500
    and
    math.max(math.max(@1st,@2nd),@3rd) - math.min(math.min(@1st,@2nd),@3rd) <= 300
}S