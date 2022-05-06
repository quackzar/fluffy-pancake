set timestamp
set title "1-to-n OT"
set key default
set xlabel "Number of Elements"
set logscale x 2
set ylabel "Runtime (ms)"
set logscale y 2

plot "data/1_to_n_ot_chou_orlandi.dat" using 1:2 title "Chou-Orlandi" with lines
