set timestamp
set title "fPAKE"
set key default
set xlabel "Number of Elements"
set logscale x 2
set ylabel "Runtime (ms)"
set logscale y 2

plot "data\fpake_password.dat" using 1:2 title "Password" with lines
