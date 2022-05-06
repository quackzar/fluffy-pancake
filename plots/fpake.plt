set timestamp
set title "fPAKE"
set key default
set xlabel "Runtime (ms)"
set logscale x 2
set ylabel "Number of X"
set logscale y 2

plot "data\fpake_password.dat" title "Password" with lines
