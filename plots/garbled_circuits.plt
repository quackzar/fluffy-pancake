set timestamp
set title "Garbled Circuits"
set key default
set xlabel "Number of Elements"
set logscale x 2
set ylabel "Runtime (ms)"
set logscale y 2

plot "data/garbled_circuits_evaluate.dat" using 1:2 title "Evaluate" with lines,"data/garbled_circuits_garble.dat" using 1:2 title "Garble" with lines
