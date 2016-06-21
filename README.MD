# Introduction

The Fathom Toolkit is a suite of tools written with the goal of helping utilize 
Nmap to better understand your environment. The core tools are written in Ruby 
and leverage Kris Katterjohn's Nmap::Parser Ruby library for searching and 
manipulating Nmap's XML output. 

The primary tool is fathom itself which parses Nmap XML output and searches 
for various data.  fp-print performs a similar function, but searches for
service and OS fingerprints.

These are the only two tools from the suite that have been published so far.
The scanning portion will be published in the coming months.



# Requirements

1. Ruby 1.9.1
	Ubuntu:
>		sudo apt-get install ruby1.9.1-full rubygems1.9.1 rdoc1.9.1
>		sudo ln -s /usr/bin/ruby1.9.1 /usr/bin/ruby

2. Ruby Nmap::Parser by Kris Katterjohn
   http://rubynmap.sourceforge.net/

	1.  Via Ruby Gems:
>	  	gem install nmap-parser

	2.  Via SourceForge download
>		http://sourceforge.net/projects/rubynmap/files/
>		Download 0.3.5 or latest
>		Unpack - Example:   tar -xvf ruby-nmap-parser-0.3.5.tgz
>		cd ruby-nmap-parser-0.3.5
>		sudo ruby setup.rb all	

	3.  Via SVN:
>		svn co https://rubynmap.svn.sourceforge.net/svnroot/rubynmap/trunk 
>		cd trunk
>		sudo ruby setup.rb all
	
# Installation

Installation instructions can be found in this project's Wiki: https://github.com/TomSellers/Fathom/wiki
