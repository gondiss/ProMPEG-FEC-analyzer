#!/bin/sh
if [ $# -lt 3 -o $# -gt 4 ] 
then
echo "\n Usage: ./filter.sh file.pcap port1(payload port) port2(fec column port) [port3](fec row port) \n"
exit 2
fi
echo "Processing $1 \n"
if [ $# -eq 3 ] 
then
./pcapfilter.o $1 $2 $3
else
./pcapfilter.o $1 $2 $3 $4
fi
if [ ! -e fec1.tmp ] 
then
echo "Processing failed"
exit 2
fi
./pcapprocess.o

rm -rf *.tmp
rm -rf debug.dat
