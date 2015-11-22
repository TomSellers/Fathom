#!/bin/bash
#  
#  scan-recon.sh v0.98.01
#
#  Perform nmap port scan on all TCP ports and a subset of UDP ports, 
#  **NO** scripts are run and **NO** version detection is performed.  
#  Exclude hosts as directed by ./lists/excludes-recon.txt, output is directed in all file formats to ./logs/
#
#  Part of the Fathom suite written by Tom Sellers <fathom_at_fadedcode.net>
#
#  Requires:	
#				nmap (5.21 or higher recommended)
#				www.nmap.org
#	

nmap -sSU -O -pT:-,U:161,162,1434,1900  --host-timeout 10m --open --excludefile ./lists/excludes-recon.txt -R --webxml -oA "./logs/$1" "$1" > "./logs/$1.txt" 2> "./logs/$1.err"

