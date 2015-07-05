#!/bin/bash
#  
#  scan-full.sh v0.97
#
#  Perform nmap port scan on all TCP ports and a subset of UDP ports, performing 
#  version detection.  Exclude hosts as directed by ./lists/excludes-full.txt
#  Output is directed in all file formats to ./logs/
#
#  Part of the Fathom suite written by Tom Sellers <fathom_at_fadedcode.net>
#
#  Requires:	
#				nmap (5.21 or higher recommended)
#				www.nmap.org
#				

nmap -sSUV -A --script "(default or safe) and not qscan"  -O -pT:-,U:53,69,137,161,523,1434,1900,2065,2067  --host-timeout 10m --version-all --open  --excludefile ./lists/excludes-full.txt -R --webxml -oA ./logs/$1 $1 > ./logs/$1.txt 2> ./logs/$1.err

