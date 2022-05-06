set timestamp
set title "OT"
set key default
set xlabel "Number of Elements"
set logscale x 2
set ylabel "Throughput in Element/s"
set logscale y 2

plot "data\ot_apricot.dat" using 1:3 title "Apricot" with lines,"data\ot_apricot_x86.dat" using 1:3 title "Apricot x86" with lines,"data\ot_chou_orlandi.dat" using 1:3 title "Chou-Orlandi" with lines
