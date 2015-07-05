#!/bin/bash
#  
#  util-genlist.sh v0.98
#
#  Take input from a text file and use it to build two lists containing all of the IP addresses, with duplicates removed, one per line.
#  One of the lists is sorted, the other randomized.
#  An exclude file is not used here as recon and full sweeps use different excludes and the lists produced by this script may be used by either.
#
#  Part of the Fathom suite written by Tom Sellers <fathom_at_fadedcode.net>
#
#  
#  Based on commands suggested by Brandon Enright <bmenrigh_at_ucsd.edu>
#  http://seclists.org/nmap-dev/2008/q4/0805.html
#

nmap -n -iL ./lists/subnets.txt  -sL -oG - | egrep '^Host' | awk '{print $2}' | sort | uniq > ./lists/scanlist.txt
cat ./lists/scanlist.txt | sort -R > ./lists/scanlist-random.txt
