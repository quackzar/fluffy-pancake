set timestamp
set title "Garbled Circuits"
set key default
set xlabel "Number of Elements"
set logscale x 2
set ylabel "Throughput in Element/s"
set logscale y 2

plot "data/garbled_circuits_evaluate.dat" using 1:3 title "Evaluate" with lines,"data/garbled_circuits_garble.dat" using 1:3 title "Garble" with lines
