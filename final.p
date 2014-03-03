 # Gnuplot script file for plotting data in file "final.dat"
 # This file is called   final.p
      set   autoscale                        # scale axes automatically
      unset log                              # remove any log-scaling
      unset label                            # remove any previous labels
      set xtic auto                          # set xtics automatically
      set ytic auto                          # set ytics automatically
      set title "RTP packet loss in Real time Network"
      set xlabel "Total Rtp packets"
      set ylabel "Lost Rtp packets"
      set linestyle 3   
      #set key 0.01,100
      #set label "Yield Point" at 0.003,260
      #set arrow from 0.0028,250 to 0.003,280
      #set xr [0.0:0.022]
      #set yr [0:325]
      plot    "final.dat" using 2 title 'Actual Loss at Network' with lines , \
            "final.dat" using 3 title 'Expected Loss after FEC correction' with lines linetype 3
      #      "final.dat" using 4 title 'Expected Loss after correction' 

