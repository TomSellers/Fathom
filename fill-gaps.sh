#!/bin/bash
#  
#  fill-gaps.sh v0.97
#
#  Input is a file (./lists/gaps.txt) containing a list of IP addresses.  
#  The script scans runs scan-recon.sh against the address ONLY if there 
#  is not currently a file set for that address in the logs directory.
#
#  Part of the Fathom suite written by Tom Sellers <fathom_at_fadedcode.net>
#
#  Requires:	
#				nmap (5.21 or higher recommended)
#				www.nmap.org
#

for ip in `cat ./lists/gaps.txt`; do
	if [ -f ./logs/$ip.xml ];
	then
	   echo `date "+%x %X"` Record exists for $ip;
	else
	   echo `date "+%x %X"` Scanning $ip;
           ./scan-recon.sh $ip;
	fi
done

