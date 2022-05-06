set timestamp
set title "One-of-many fPAKE"
set key default
set xlabel "Runtime (ms)"
set logscale x 2
set ylabel "Number of X"
set logscale y 2

plot "data\one_of_many_fpake_v1_v1.dat" title "v1,v1" with lines,"data\one_of_many_fpake_v1_v2.dat" title "v1,v2" with lines,"data\one_of_many_fpake_v2_v1.dat" title "v2,v1" with lines,"data\one_of_many_fpake_v2_v2.dat" title "v2,v2" with lines
