#!/usr/bin/env ruby
#  
#  fp-list.rb
#
#  Nmap xml output query tool by Tom Sellers
#  Searches XML output for OS and service fingerprint data
#
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

PROG_VERSION = '0.98.01'


require 'nmap/parser' 
require 'optparse'
require 'ipaddr'
require 'date'

$log_path = "./logs/"

$ip_filter = nil
$reportfile = nil

begin 
  $error_message = nil
  $params = ParseArgs.parse(ARGV)
  
  # Set the XML location to the default if one is not specified on the command line
  if !$listing
    if File.directory?($log_path)
      $listing = Dir.glob("#{$log_path}/*.xml")
    else
      puts
      puts "Error: Default log directory ( #{$log_path} ) does not exist or cannot be accessed."
      puts "       Use -l or --log <location> to specify a Nmap XML file or directory containing the XML files"
      puts
      exit
    end
  end

  
  if $params['Report_File']
    $reportfile = File.new($params['Report_File'], 'w')
  end
  
  if $params['Metrics']
    statistics $params['Metric_counter']
    exit
  end
  
  if !($params['Service'] or $params['OS']) then
    $params['Service'] = true
    $params['OS'] = true
    puts 'Searching for both service and OS fingerprints....'
    puts
    
  end  #  !($params['Service'] or $params['OS'])

  if ($params['Service']) and !($params['OS'] )
    if $params['Format_csv']
      if $reportfile
        $reportfile.puts 'IP address,hostname,port,service,OS name,scan date'
      else
        puts 'IP address,hostname,port,service,OS name,scan date'
      end      
    end
  end



  $listing.each { |file|

    begin
      parser = Nmap::Parser.parsefile(file)

    rescue Interrupt
      exit_interrupt

    rescue

      if $error_message
        $error_message = $error_message + "\r\nError parsing #{file}."
      else
        $error_message = "Error parsing #{file}."
      end # $error_message
    
    else
          parser.hosts("up") do |host|
      
      if $ip_filter
        if !$ip_filter.include?(IPAddr.new(host.ip4_addr))
          next
        end
      end

      timestamp = Time.at(parser.session.start_time).strftime('%Y/%m/%d %X')

      if $params['Start_date']
        scan_date = Date.parse(timestamp)
        #skip this file if it is not in the date range we want
        next if scan_date < $params['Start_date']
      end

      if $params['End_date']
        scan_date = Date.parse(timestamp)
        #skip this file if it is not in the date range we want
        next if scan_date > $params['End_date']
      end

      if $params['Service'] then

        host.getports('any', 'open') do |port|

          if $params['Port'] then 

            if $params['Port'] ==  port.num then
              port_output(host, port, timestamp)
            end  # if $params['Port'] == port.num...

          elsif $params['Exclude_port']

            if $params['Exclude_port'] !=  port.num then
              port_output(host, port, timestamp)
            end  # if $params['Exclude_port'] != port.num...

          elsif $params['Service_name']

            if $params['Service_name'] ==  port.service.name then
              port_output(host, port, timestamp)
            end  # if $params['Service_name'] == port.service.name

          else

            port_output(host, port, timestamp)

          end  # if $params['Port']...          

        end  # host.getports...

      end  # if $params['Service']...

      if $params['OS'] then

        if host.os.fingerprint then
          timestamp = Time.at(parser.session.start_time).strftime("%Y/%m/%d %X")    

          if $params['Start_date']
            scan_date = Date.parse(timestamp)
            #skip this file if it is not in the date range we want
            next if scan_date < $params['Start_date']
          end

          if $params['End_date']
            scan_date = Date.parse(timestamp)
            #skip this file if it is not in the date range we want
            next if scan_date > $params['End_date']
          end          

          if $reportfile
            if $params['Format_bare']
              $reportfile.puts "#{host.addr}"
            elsif $params['Format_csv']
              $reportfile.puts "#{host.addr},#{host.hostname},na,unknown fingerprint,\"#{timestamp}\""
            else
              $reportfile.puts "Host:        #{host.addr} (#{host.hostname})"
              $reportfile.puts "Record date: #{timestamp}"
              $reportfile.puts "\nOS Fingerprint:"
              $reportfile.puts
              $reportfile.puts host.os.fingerprint
              $reportfile.puts
              $reportfile.puts
            end  # format_bare
          else
            if $params['Format_bare']
              puts "#{host.addr}"
            elsif $params['Format_csv']
              puts "#{host.addr},#{host.hostname},na,unknown fingerprint,\"#{timestamp}\""
            else
              puts "Host:        #{host.addr} (#{host.hostname})"
              puts "Record date: #{timestamp}"
              puts "\nOS Fingerprint:"
              puts
              puts host.os.fingerprint
              puts
              puts
            end  # format_bare
          end

          timestamp = nil

        end  # if os.fingerprint

      end  # if $params['OS']...

      timestamp = nil
      end  # parser.host..

    end  # begin

  }  #$listing.each { |file|

  if $error_message
    puts
    puts
    puts '##############################################################################'
    puts 'Errors during operation:'
    puts $error_message
    puts '##############################################################################'
  end # $error_message

rescue Interrupt
  puts
  puts
  puts 'Search canceled by user...'
  puts
  if $error_message
    puts '##############################################################################'
    puts 'Errors during operation:'
    puts $error_message
    puts '##############################################################################'
  end # $error_message
    
end  #begin

# ----- Method Definitions -----

BEGIN  {

class ParseArgs

  def self.parse(args)
    options = {}

    opts = OptionParser.new do |opts|
      opts.banner = 'Usage: fp-list.rb [options]'

      opts.separator ''
      opts.separator 'Query options:'

      opts.on('-p', '--port <number>', 'Search for specified port number') do |p|
        options['Port'] = p.to_i
        options['Service'] = true
      end    

      opts.on('-s', '--service [string]', 'Return service fingerprints, optionally include service name to search for') do |s|
        if s != nil
          options['Service_name'] = s.downcase
        end
        options['Service'] = true
      end

      opts.on('-o', '--operating-system', 'Return OS fingerprints') do |o|
        options['OS'] = true
      end

      opts.separator ''
      opts.separator 'Filter options:'

      opts.on('--ip-filter <ip_address>', 'Filter results by IP Address',
              'Acceptable formats are as a single IP address   (xxx.xxx.xxx.xxx)',
              'or in IP/CIDR notation                          (xxx.xxx.xxx.xxx/xx)',
              'or in IP/netmask notation                       (xxx.xxx.xxx.xxx/xxx.xxx.xxx.xxx)') do |address_filter|

        # validate ip filter
        # check for format xxx.xxx.xxx.xxx
        valid_filter = true if address_filter.to_s =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/

        # check for format xxx.xxx.xxx.xxx/xx
        valid_filter = true if address_filter.to_s =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/

        # check for format xxx.xxx.xxx.xxx/xxx.xxx.xxx.xxx (netmask)
        valid_filter = true if address_filter.to_s =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/


        if valid_filter
          $ip_filter = IPAddr.new address_filter.to_s
        else
          puts
          puts 'Error: Option passed for network address does not appear valid. Use -h to see valid formats.'
          puts
          exit
        end # if valid_filter

      end

      opts.on('--start-date <YYYY-MM-DD>', 'Limit output to hosts scanned ON or AFTER the specified date, valid delimiters are . / and -') do |start_date|
        if start_date.to_s =~ /^\d{4}[.\/-]\d{1,2}[.\/-]\d{1,2}$/
          options['Start_date'] = Date.parse($&)
        else
          puts
          puts 'Error: Option passed for start date does not appear valid. Use -h to see valid formats.'
          puts
          exit
        end        
      end

      opts.on('--end-date <YYYY-MM-DD>', 'Limit output to hosts scanned ON or BEFORE the specified date, valid delimiters are . / and -') do |end_date|
        if end_date.to_s =~ /^\d{4}[.\/-]\d{1,2}[.\/-]\d{1,2}$/
          options['End_date'] = Date.parse($&)
        else
          puts
          puts 'Error: Option passed for end date does not appear valid. Use -h to see valid formats.'
          puts
          exit
        end        
      end

      opts.on('-e', '--exclude-port <number>', 'Exclude results matching the specified port') do |e|
        options['Exclude_port'] = e.to_i
      end      

      opts.separator ''
      opts.separator 'Misc options:'

      opts.on('-l', '--log <location>', 'Specify a particular Nmap XML file or the location of the directory containing Nmap XML logs') do |l|
        if File.directory?(l) && File.readable?(l)
          $log_path = l
        elsif File.file?(l) && File.readable?(l)
          $listing = Array.new
          $listing[0] = l.to_s
        else
          puts
          puts "Error:  Specified file or log directory ( #{l} ) does not exist or cannot be accessed"
          exit
        end
      end  

      opts.on('-r', '--report <filename>', 'Output results to specified file, as opposed to the terminal') do |r|
        if File.exist?(r)
          if !File.writable?(r)
            puts
            puts "Error:  Specified output (#{r}) file exists, but cannot be written to."
            puts '        The file may be locked or your account may not have permssion to write to it.'
            exit
          end
        end
        
        options['Report_File'] = r.to_s
                      
      end
      
      opts.on('-b', '--bare', 'Output IP Address only') do
        options['Format_bare'] = true
      end
      
      opts.on('-c', '--csv', 'Output results in CSV format') do
        options['Format_csv'] = true
      end

      opts.on('--metrics [number]', 'Generate OS and port statistics, optionally limit result count') do |count|
        if count.to_i > 0
          options['Metric_counter'] = count.to_i 
        else
          options['Metric_counter'] = nil
        end
        options['Metrics'] = true
      end
      
      opts.separator ''
      
      opts.on('-v', '--version', 'Show version information') do
        puts
        puts "\tfp-list #{PROG_VERSION} by Tom Sellers"
        puts 
        puts "\tSupporting software versions:"
        puts "\t\tRuby version:          #{RUBY_VERSION}"
        puts "\t\tNmap::Parser version:  #{Nmap::Parser::Version} #{Nmap::Parser::Stage}"
        exit
      end  

      opts.on_tail('-h', '--help', 'Show this message') do
        puts opts
        exit
      end
    end

    begin
      opts.parse!(args)
    rescue OptionParser::InvalidOption
      puts 'Invalid option, try -h for usage'
      exit
    end

    options
  
  end  #self.parse(args)

end  #ParseArgs

def exit_interrupt

  puts
  puts
  puts 'Search canceled by user...'
  puts
  if $error_message
    puts '##############################################################################'
    puts 'Errors during operation:'
    puts $error_message
    puts '##############################################################################'
  end # $error_message

  $reportfile.close if $reportfile
  exit

end # exit_interrupt

def port_output(host, port, timestamp)
  
  srv = port.service
  os = host.os

  if srv.fingerprint then
    if $reportfile
      if $params['Format_bare']
        $reportfile.puts "#{host.addr}"
      elsif $params['Format_csv']
        if srv.name
          $reportfile.puts "#{host.addr},#{host.hostname},#{port.num}/#{port.proto},#{srv.name},\"#{os.name}\",\"#{timestamp}\""
        else
          $reportfile.puts "#{host.addr},#{host.hostname},#{port.num}/#{port.proto},,\"#{os.name}\",\"#{timestamp}\""
        end
      else
        $reportfile.puts "Host:        #{host.addr} (#{host.hostname})"
        $reportfile.puts "Port:        #{port.num}/#{port.proto}"
        $reportfile.puts "Service:     #{srv.name}" if srv.name
        $reportfile.puts "Record date: #{timestamp}"
        $reportfile.puts "\nService Fingerprint:"
        $reportfile.puts
        $reportfile.puts srv.fingerprint
        $reportfile.puts
        $reportfile.puts
      end  # $params['Format_bare']
    else
      if $params['Format_bare']
        puts "#{host.addr}"
      elsif $params['Format_csv']
        if srv.name
          puts "#{host.addr},#{host.hostname},#{port.num}/#{port.proto},#{srv.name},\"#{os.name}\",\"#{timestamp}\""
        else
          puts "#{host.addr},#{host.hostname},#{port.num}/#{port.proto},,\"#{os.name}\",\"#{timestamp}\""
        end
      else
        puts "Host:        #{host.addr} (#{host.hostname})"
        puts "Port:        #{port.num}/#{port.proto}"
        puts "Service:     #{srv.name}" if srv.name
        puts "Record date: #{timestamp}"
        puts "\nService Fingerprint:"
        puts
        puts srv.fingerprint
        puts
        puts
      end  # $params['Format_bare']
    end  # $reportfile


  end  # if srv.fingerprint..

end  # port_output (port)

def statistics(counter)

  os_stats = 0
  host_counter = 0
  port_stats = Hash.new(0)

  $listing.each { |file|

    begin
      parser = Nmap::Parser.parsefile(file)
    rescue

      if $error_message
        $error_message = $error_message + "\r\nError parsing #{file}.\r\n"
      else
        $error_message = "Error parsing #{file}."
      end # $error_message

    else

      parser.hosts("up") do |host|

        if $ip_filter
          if !$ip_filter.include?(IPAddr.new(host.ip4_addr))
            next
          end
        end

        host_counter = host_counter + 1


        if host.os.fingerprint
          os_stats = os_stats + 1        
        end # if os.fingerprint

        host.getports(:any,'open') do |port|

          if port.service.fingerprint

            port_stats["#{port.num}/#{port.proto}"] += 1

          end #if port.service.fingerprint

        end  #host.getports(:any,"open") do |port|

      end #parser.hosts("up") do |host|

    end

  }

  puts
  puts "The specified subset of logs contain information on #{host_counter} hosts."
  puts "There are #{os_stats} OS fingerprint(s) in the logs currently."
  puts
  puts 'Port Fingerprint statistics'
  puts
  puts 'Count  Port'
  # Reverse sort the hash table (thats the -1 part), then iterate through the temporary
  # array and display the results.

  port_stats.sort {|a,b| -1*(a[1]<=>b[1])}.each_with_index { |item, index|
    break if counter and index.to_i == counter
    puts sprintf("%5d  %s ",item[1],item[0])
  }

  puts
  puts

end #statistics

}


