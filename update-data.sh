#!/bin/bash
#  
#  update-data.sh v0.97
#
#  Cycle through log directory and rescan each hosts, starting with the oldest first.
#  The script runs scan-full.sh against each address.
#  
#
#  Part of the Fathom suite written by Tom Sellers <fathom_at_fadedcode.net>
#
#  Requires:	
#				nmap (5.21 or higher recommended)
#				www.nmap.org
#

for f in `ls -tr ./logs/*.xml`; do
	f=${f#./logs/}		#strip off ./logs/
	f=${f%%.xml} 		#strip off the .xml filename extension
        echo `date` "Processing $f"
	./scan-full.sh $f
done

