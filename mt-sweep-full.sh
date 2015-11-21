#!/bin/bash
#  
#  sweep-full.sh v0.98.01
#
#  The purpose of this script is to peform a full (intensive) scan against a 
#  list of hosts.  Input is a file (./lists/scanlist-random.txt) containing a 
#  list of IP addresses. The script runs scan-full.sh against each address.
#
#  Part of the Fathom suite written by Tom Sellers <fathom_at_fadedcode.net>
#
#  Requires:	
#				nmap (5.21 or higher recommended)
#				www.nmap.org
#


xargs --arg-file=./lists/scanlist-random.txt --max-procs=3 -I IP ./scan-full.sh IP

