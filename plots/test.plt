set timestamp
set title "One-of-many fPAKE"

set xlabel "Number of passwords"
set logscale x 2

set ylabel "Runtime (ms)"
set logscale y 2

set key default

plot "fpake_v1v1.dat" title "fPAKE v1,v1" with lines, "fpake_v1v2.dat" title "fPAKE v1,v2"  with lines, "fpake_v2v1.dat" title "fPAKE v2,v1" with lines, "fpake_v2v2.dat" title "fPAKE v2,v2" with lines