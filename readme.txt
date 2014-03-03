1. untar the pcapf.tgz file
2. filter/ folder will contain filter.sh, filter.p(script for gnu plot),readme (this file), pcapfilter.o & pcapprocess.o (this are the precompiled executables can also be compiled from source tar)
3. copy the pcap file to be analysed to filter/ directory.
4. cd to filter/ and run as ./filter.sh to get help.
5. do gnuplot and load "final.p"

dependencies: 
1. libpcap & libpcap-devel >= 0.9.7.3 
2. gnuplot
