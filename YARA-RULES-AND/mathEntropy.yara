import "math"

rule PE_High_Entropy_LAst_1KB {
      condition:
        math.entropy(filesize-1000,filesize) > 7.9
}