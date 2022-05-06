set timestamp
set title "One-of-many fPAKE"
set key default
set xlabel "Number of Elements"
set logscale x 2
set ylabel "Runtime (ms)"
set logscale y 2

plot "data/one_of_many_fpake_v1_v2.dat" using 1:2 title "v1,v2" with lines,"data/one_of_many_fpake_v2_v1.dat" using 1:2 title "v2,v1" with lines,"data/one_of_many_fpake_v1_v1.dat" using 1:2 title "v1,v1" with lines,"data/one_of_many_fpake_v2_v2.dat" using 1:2 title "v2,v2" with lines
