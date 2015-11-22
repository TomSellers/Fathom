#!/bin/bash
#  
#  sweep-recon.sh v0.98.01
#
#  The purpose of this script is to peform a recon (port scan only) scan against a list of hosts.
#  Input is a file (./lists/scanlist-random.txt) containing a list of IP addresses.  
#  The script runs scan-recon.sh against each address.
#
#  Part of the Fathom suite written by Tom Sellers <fathom_at_fadedcode.net>
#
#  Requires:	
#				nmap (5.21 or higher recommended)
#				www.nmap.org
#

for ip in $(cat ./lists/scanlist-random.txt); do 
	echo "$(date "+%x %X")" Scanning "$ip";
	./scan-recon.sh "$ip";
done
