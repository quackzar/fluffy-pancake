set title "Polynomial Multiply Reduce"
set key default
set xlabel "Number of Element"
set logscale x 2
set ylabel "Runtime"
set logscale y 2
set term pdf font "Computer Modern,10"
set output "out/polynomial_multiply_reduce.pdf"

set xtics ("2^{1}" 2, "2^{2}" 4, "2^{3}" 8, "2^{4}" 16, "2^{5}" 32, "2^{6}" 64, "2^{7}" 128, "2^{8}" 256, "2^{9}" 512, "2^{10}" 1024, "2^{11}" 2048, "2^{12}" 4096, "2^{13}" 8192, "2^{14}" 16384, "2^{15}" 32768, "2^{16}" 65536, "2^{17}" 131072, "2^{18}" 262144, "2^{19}" 524288, "2^{20}" 1048576, "2^{21}" 2097152, "2^{22}" 4194304, "2^{23}" 8388608, "2^{24}" 16777216, "2^{25}" 33554432, "2^{26}" 67108864, "2^{27}" 134217728, "2^{28}" 268435456, "2^{29}" 536870912, "2^{30}" 1073741824)

set ytics ("1 ms" 1, "2 ms" 2, "4 ms" 4, "8 ms" 8, "16 ms" 16, "32 ms" 32, "64 ms" 64, "128 ms" 128, "256 ms" 256, "512 ms" 512, "1.02 s" 1024, "2.05 s" 2048, "4.10 s" 4096, "8.19 s" 8192, "16.38 s" 16384, "32.77 s" 32768, "65.54 s" 65536, "131.07 s" 131072, "262.14 s" 262144, "524.29 s" 524288, "1,048.58 s" 1048576, "2,097.15 s" 2097152, "4,194.30 s" 4194304, "8,388.61 s" 8388608, "16,777.22 s" 16777216, "33,554.43 s" 33554432, "67,108.86 s" 67108864, "134,217.73 s" 134217728, "268,435.46 s" 268435456, "536,870.91 s" 536870912)

plot "data/polynomial_multiply_reduce_generic_implementation.dat" using 1:2 title "Generic Implementation" with lines,"data/polynomial_multiply_reduce_x86_implementation.dat" using 1:2 title "x86 Implementation" with lines
