# Introduction

The Fathom Toolkit is a suite of tools written with the goal of helping utilize 
Nmap to better understand your environment. The core tools are written in Ruby 
and leverage Kris Katterjohn's Nmap::Parser Ruby library for searching and 
manipulating Nmap's XML output. 

The primary tool is fathom itself which parses Nmap XML output and searches 
for various data.  fp-print performs a similar function, but searches for
service and OS fingerprints.

| Tool | Summary|
| :---- | :-------|
| fathom.rb | Searches Nmap XML output for various data related to ports, services, etc. |
| cert-query.rb | Returns results based on x509 certificate based criteria ( thumbprint, expiration, etc.) |
| fp-list.rb | Searches Nmap XML for fingerprint output blocks related to unknown services and OSes |
| report.sh | When provided with an IP, returns the Nmap results for that IP if it exists |
| scan-full.sh | Full scan (scripts/ver detection) of a single user provided IP address |
| sweep-full.sh | Full scan (scripts/ver detection) of every IP in ./lists/scanlist-random.txt, one at a time |
| mt-sweep-full.sh | Full scan (scripts/ver detection) of every IP in ./list/scanlist-random.txt, multiple targets at a time |
| scan-recon.sh | Port scan only of a single user provided IP address |
| sweep-recon.sh | Port scan only of every IP in ./lists/scanlist-random.txt, one at a time |
| update-data.sh | Rescans hosts in the ./logs/ directory starting with the oldest, one at a time |
| mt-update-data.sh | Rescans hosts in the ./logs/ directory starting with the oldest, multiple targets at a time |
| util-genlist.sh | Takes all subnets in ./lists/subnets.txt, expands, randomizes, and saves to ./lists/scanlist-random.txt |


# Installation

Installation instructions can be found in this project's Wiki: https://github.com/TomSellers/Fathom/wiki
