#!/bin/bash
#  
#  scan-full.sh v0.98
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
echo "$(date)" "Processing $1"

nmap -sSU -A --script "(default or safe or ssl-enum-ciphers or http-auth-finder ) and not (http-default-accounts or http-mobileversion-checker or http-comments-displayer or http-slowloris-check or p2p-conficker or qscan or path-mtu or broadcast or external or smb-mbenum or firewalk or reverse-index or url-snarf or http-useragent-tester or http-grep)" -vvv  -PS21,22,23,25,53,80,135,139,389,443,445,636,3389 -pT:-,U:53,69,123,137,161,251,500,523,1434,1900,2065,2067,4500  --host-timeout 20m --version-all --open  --excludefile ./lists/excludes-full.txt -R --webxml -oA "./logs/$1" "$1" > "./logs/$1.txt" 2> "./logs/$1.err"


./util-checkhost.rb --filename "$1.xml"

echo "$(date)" "     Completed $1"

