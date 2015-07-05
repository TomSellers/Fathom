#!/usr/bin/env ruby
#  
#  util-cleanup.rb
#
#  utility to move nmap XML files containing 0 hosts to a backup directory
#  and out of the logs directory.  Speeds query processes of both fathom.rb
#  and fp-list.rb
#
#  Part of the Fathom suite written by Tom Sellers <fathom_at_fadedcode.net>
#
#  Requires:  
#        Ruby (1.9.1 recommended)
#
#        Kris Katterjohn's Ruby Nmap::Parser
#               http://rubynmap.sourceforge.net/
#
#  License
#  Copyright (c) 2015 Tom Sellers
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#  THE SOFTWARE.

Prog_version = '0.98'

require 'nmap/parser' 
require 'optparse'
require 'fileutils'
require 'ipaddr'

$ip_filter = nil


$backup = "./logs/backup"
$params = ParseArgs.parse(ARGV)

if $params['purge']
  puts "Are you sure you wish to delete everything in the #{$backup} directory? (y/n)"
  verify = gets
  exit if verify == nil
  verify.chomp!
  if verify != 'y' and verify !='Y'
    exit
  end
  
  FileUtils.rm Dir.glob($backup + "/*"), :force => true
  
  exit  
end

listing = Dir.glob("./logs/*.xml")

listing.each { |file|

  begin
    parser = Nmap::Parser.parsefile(file)
  rescue
  
    if $error_message
      $error_message = $error_message + "\r\n" + "Error parsing #{file}." 
    else
      $error_message = "Error parsing #{file}."
    end # $error_message
  
  else
    if parser.hosts("up").count == 0 then
    
      filepath = file.gsub(".xml",".*")
      puts "Moving #{filepath}, #{parser.hosts("up").count} hosts in this file group."
      FileUtils.mv Dir.glob(filepath), $backup
    
    elsif $ip_filter
    
      parser.hosts("up") do |host|
        if $ip_filter.include?(IPAddr.new(host.ip4_addr))
          filepath = file.gsub(".xml",".*")
          puts "Moving #{filepath} due to IP Address selection.\n\t#{parser.hosts("up").count} hosts in this file group."
          FileUtils.mv Dir.glob(filepath), $backup
      
        end
      end
        
    end
  
  end  # begin

}

if $error_message
  puts
  puts
  puts "##############################################################################"
  puts "Errors during operation:"
  puts $error_message
  puts "##############################################################################"
end # $error_message

# ----- Method Definitions -----

BEGIN  {

class ParseArgs
  
  def self.parse(args)
    options = {}

    legal_option = nil
    
    opts = OptionParser.new do |opts|
    
      opts.banner = "Usage: util-cleanup.rb [options]"

      opts.separator ""
      opts.separator "Options:"
      
      opts.on("--archive", "Move data files containing 0 hosts to backup directory (#{$backup})") do
        legal_option = true
      end
      
      opts.on("--purge", "Delete all files in the backup directory (#{$backup})") do
        options['purge'] = true
        legal_option = true
      end
      
      opts.separator ""
      opts.separator "Selection options:"
      
      opts.on("--ip-filter <ip_address>", "Select files containing certain IP Addresses",
                                          "Acceptable formats are as a single IP address   (xxx.xxx.xxx.xxx)",
                        "or in IP/CIDR notation                          (xxx.xxx.xxx.xxx/xx)",
                        "or in IP/netmask notation                       (xxx.xxx.xxx.xxx/xxx.xxx.xxx.xxx)") do |address_filter|

        # validate ip filter
        # check for format xxx.xxx.xxx.xxx
        valid_filter = true if (address_filter.to_s =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)
        
        # check for format xxx.xxx.xxx.xxx/xx
        valid_filter = true if (address_filter.to_s =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/)
        
        # check for format xxx.xxx.xxx.xxx/xxx.xxx.xxx.xxx (netmask)
        valid_filter = true if (address_filter.to_s =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)
                
        if valid_filter
          $ip_filter = IPAddr.new address_filter.to_s
          legal_option = true
        else
          puts
          puts "Error: Option passed for network address does not appear valid. Use -h to see valid formats."
          puts
          exit
        end # if valid_filter
      end
    
      opts.separator ""
      
      opts.on("-v", "--version", "Show version information") do
        puts
        puts "\tutil-cleanup #{Prog_version} by Tom Sellers"
        puts 
        puts "\tSupporting software versions:"
        puts "\t\tRuby version:          #{RUBY_VERSION}"
        puts "\t\tNmap::Parser version:  #{Nmap::Parser::Version} #{Nmap::Parser::Stage}"
        exit
      end  

    end

    begin
      opts.parse!(args)
    rescue OptionParser::InvalidOption
      puts "Invalid option, try -h for usage"
      exit
    end
    
    if !legal_option
      puts "Error: No search criteria selected..."
      puts
      puts opts
      exit
    end

    options
  
  end  #self.parse(args)

end  #ParseArgs

}
