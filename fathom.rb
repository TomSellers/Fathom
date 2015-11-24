#!/usr/bin/env ruby
#
#  fathom.rb
#
#  Searches nmap XML output for port, service, script output or OS
#
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

$log_path = './logs'

$ip_filter = nil
$reportfile = nil

begin
  $error_message = nil
  $params = ParseArgs.parse(ARGV)

  # Set the XML path to the default if one is not specified on the command line
  unless $listing
    if File.directory?($log_path)
      $listing = Dir.glob("#{$log_path}/*.xml")
    else
      puts
      puts "Error: Default log directory ( #{$log_path} ) does not exist or cannot be accessed."
      puts '       Use -l or --log <location> to specify a Nmap XML file or directory containing the XML files'
      puts
      exit
    end
  end

  # Sort the file list, it won't sort the IPs properly but it is better than
  # the scattershot listing before.
  $listing.sort!

  $reportfile = File.new($params['Report_File'], 'w') if $params['Report_File']

  if $params['Metrics']
    statistics $params['Metric_counter']
    exit
  end

  if $params['Port']

    puts
    if $params['Format_csv']
      if $reportfile
        $reportfile.puts 'IP address,hostname,port,service,product,version,extra info,scan date'
      else
        puts 'IP address,hostname,port,service,product,version,extra info,scan date'
      end
    end

    port_search $params['Port']

    # Exit cleanly
    exit_normal

  end

  if $params['Service']

    puts
    if $params['Format_csv']
      if $reportfile
        $reportfile.puts 'IP address,hostname,port,service,product,version,extra info,scan date'
      else
        puts 'IP address,hostname,port,service,product,version,extra info,scan date'
      end
    end

    service_search $params['Service']
  end

  if $params['OS'] || $params['All']
    puts
    os_search $params['OS']
  end

  if $params['MAC']
    puts
    mac_search $params['MAC']
  end

  
  script_search $params['Script_data'] if $params['Script_data']

  # Exit cleanly
  exit_normal

rescue Interrupt
  exit_interrupt


end

########################################################
# ---------------- Method Definitions ---------------- #
########################################################

BEGIN  {

class ParseArgs

  def self.parse(args)
    options = {}

    legal_option = nil

    opts = OptionParser.new do |opts|
      opts.banner = 'Usage: fathom.rb [options]'

      opts.separator ''
      opts.separator 'Query options:'

      opts.on('-p', '--port <number>', 'Search for specified port number') do |p|
        options['Port'] = p.to_i
        legal_option = true
      end

      opts.on('-s', '--service <string>', 'Search service, product and information fields for the specified string') do |s|
        options['Service'] = s.downcase
        legal_option = true
      end

      opts.on('-o', '--operating-system <string>', 'Search for specified OS string') do |o|
        options['OS'] = o.downcase
        legal_option = true
      end

      opts.on('-m', '--mac-address <string>', 'Search for specified MAC address or vendor string') do |m|
        options['MAC'] = m.downcase
        legal_option = true
      end

      opts.on('-a', '--all-hosts', 'Return a list of all hosts in the logs') do
        options['All'] = true
        legal_option = true
      end

      opts.separator ''
      opts.separator 'Filter options:'

      opts.on('--ip-filter <ip_address>', 'Filter results by IP Address',
                                          'Acceptable formats are as a single IP address   (xxx.xxx.xxx.xxx)',
                        'or in IP/CIDR notation                          (xxx.xxx.xxx.xxx/xx)',
                        'or in IP/netmask notation                       (xxx.xxx.xxx.xxx/xxx.xxx.xxx.xxx)') do |address_filter|

        # validate ip filter
        # check for format xxx.xxx.xxx.xxx
        valid_filter = true if address_filter.to_s =~ %r{^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$}

        # check for format xxx.xxx.xxx.xxx/xx
        valid_filter = true if address_filter.to_s =~ %r{^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$}

        # check for format xxx.xxx.xxx.xxx/xxx.xxx.xxx.xxx (netmask)
        valid_filter = true if address_filter.to_s =~ %r{^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$}

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
        if start_date.to_s =~ %r{^\d{4}[.\/-]\d{1,2}[.\/-]\d{1,2}$}
          options['Start_date'] = Date.parse($&)
        else
          puts
          puts 'Error: Option passed for start date does not appear valid. Use -h to see valid formats.'
          puts
          exit
        end
      end

      opts.on('--end-date <YYYY-MM-DD>', 'Limit output to hosts scanned ON or BEFORE the specified date, valid delimiters are . / and -') do |end_date|
        if end_date.to_s =~ %r{^\d{4}[.\/-]\d{1,2}[.\/-]\d{1,2}$}
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

      opts.on('-x', '--exclude-service <string>', 'Exclude service where the service name or product matches the specified string') do |x|
        options['Exclude'] = x.downcase
      end

      opts.on('--exclude-os <string>', 'Exclude results matching the specified OS (if the OS is identified by Nmap)') do |exclude_os|
        options['Exclude_os'] = exclude_os.downcase
      end

      opts.separator ''
      opts.separator 'Misc options:'

      opts.on('-l', '--log <location>', 'Specify a particular Nmap XML file or the location of the directory containing Nmap XML logs') do |l|
        if  File.directory?(l) && File.readable?(l)
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
          unless File.writable?(r)
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
        legal_option = true
      end

      opts.on('--script-data <string>', 'Search NSE script result data (case insensitive)') do |script_data|
        options['Script_data'] = script_data.downcase
        legal_option = true
      end

      opts.separator ''

      opts.on('-v', '--version', 'Show version information') do
        puts
        puts "\tfathom #{PROG_VERSION} by Tom Sellers"
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

    unless legal_option
      puts 'Error: No search criteria selected...'
      puts
      puts opts
      exit
    end

    options

  end  # self.parse(args)

end  # ParseArgs

def exit_interrupt

  puts
  puts
  puts 'Search canceled by user...'
  puts
  if $error_message
    puts '##############################################################################'
    puts '# Errors during operation:'
    puts "# #{$error_message}"
    puts '##############################################################################'
  end # $error_message

  $reportfile.close if $reportfile
  exit

end # exit_interrupt

def exit_normal

  if $error_message
    puts
    puts
    puts '##############################################################################'
    puts '# Errors during operation:'
    puts "# #{$error_message}"
    puts '##############################################################################'
  end # $error_message

  $reportfile.close if $reportfile
  exit

end # clean_exit

def gen_output(host, port, srv, timestamp, script = '')

  if $ip_filter
    return unless $ip_filter.include?(IPAddr.new(host.ip4_addr))
  end

  # Filter excluded ports
  return if $params['Exclude_port'] && port.num == $params['Exclude_port']

  # Handle specifically excluded OSes
  if $params['Exclude_os']

    host_os = host.os.name

    if host_os
      host_os = host_os.downcase
      return if host_os.include?($params['Exclude_os'])
    end
  end

  # Allow output to be limited to just certain Oses
  if $params['OS']

    host_os = host.os.name

    if host_os
      host_os = host_os.downcase
      return unless host_os.include?($params['OS'])
    else
      # if host_os is not defined, we skip the host
      return
    end # if host_os
  end

  # Handle specifically excluded services
  if $params['Exclude']

    if srv.product
      portstring = srv.product
      portstring = portstring.downcase
      return if portstring.include?($params['Exclude'])
    end # srv.product

  end  # if $params['Exclude']

  # Build output string
  if $params['Format_bare']
    result_string = "#{host.addr}"
  elsif $params['Format_csv']

    if $params['Script_data']
      if (port != '') && (srv != '')
        result_string = "#{host.addr},#{host.hostname},#{port.num}/#{port.proto},#{srv.name},\"#{srv.product}\",\"#{srv.version}\",\"#{srv.extra}\",#{script.id},\"#{timestamp}\""
      else
        result_string = "#{host.addr},#{host.hostname},,,,,,#{script.id},\"#{timestamp}\""
      end

    else
      if (port != '') && (srv != '')
        result_string = "#{host.addr},#{host.hostname},#{port.num}/#{port.proto},#{srv.name},\"#{srv.product}\",\"#{srv.version}\",\"#{srv.extra}\",\"#{timestamp}\""
      else
        result_string = "#{host.addr},#{host.hostname},,,,,,\"#{timestamp}\""
      end
    end

  else

    if $params['Script_data']
      result_string = "Host:        #{host.addr} (#{host.hostname})\n"
      
      result_string += "Port:        #{port.num}/#{port.proto}\n" if port != ''

      result_string += "Service:     #{srv.name}\n" if srv != ''
      result_string += "Record date: #{timestamp}\n"
      result_string += "\nScript name: #{script.id}\n\n"
      result_string += script.output
      result_string += "\n\n"
    else
      if (port) && (srv)
        result_string = sprintf('%-15s %-30.30s %5d/%-3s %-12.12s %-20.20s %-10.10s %-30.30s %-19s', host.addr, host.hostname, port.num, port.proto, srv.name, srv.product, srv.version, srv.extra, timestamp)
        # result_string = "#{host.addr}\t#{host.hostname}\t#{port.num}/#{port.proto}\t#{srv.name}\t#{srv.product}\t#{srv.version}\t#{srv.extra}\t#{timestamp}"
      else
        result_string = sprintf('%-15s %-30.30s                                                                         %-19s', host.addr, host.hostname, timestamp)
        # result_string = "#{host.addr}\t#{host.hostname}\t\t\t\t\t\t#{timestamp}"
      end
    end


  end  # $params['Format_bare']

  # Write result to appropriate media
  if $reportfile
    $reportfile.puts result_string
  else
    puts result_string
  end # $reportfile

  result_string = nil

end  # gen_output (host,port,srv,timestamp, script="")

def port_search(port_num)

  $listing.each { |file|

    begin
      parser = Nmap::Parser.parsefile(file)

    rescue Interrupt
      exit_interrupt

    rescue

      if $error_message
        $error_message = $error_message + "\r\n" + "Error parsing #{file}."
      else
        $error_message = "Error parsing #{file}."
      end # $error_message

    else
      timestamp = Time.at(parser.session.start_time).strftime('%Y/%m/%d %X')

      if $params['Start_date']
        scan_date = Date.parse(timestamp)
        # skip this file if it is not in the date range we want
        next if scan_date < $params['Start_date']
      end

      if $params['End_date']
        scan_date = Date.parse(timestamp)
        # skip this file if it is not in the date range we want
        next if scan_date > $params['End_date']
      end

      parser.hosts('up') do |host|

        host.getports(:any, 'open') do |port|
          next if (port.state == 'open|filtered') && (port.reason == 'no-response')
          if port.num == port_num
            srv = port.service
            gen_output host, port, srv, timestamp
          end  # if port.num
        end  # host.getports

      end  # parser.host..

      timestamp = nil
    end  # begin
  }

end  # port_search (port_num)

def service_search(service_string)

  foundmatch = nil

  $listing.each { |file|

    begin
      parser = Nmap::Parser.parsefile(file)

    rescue Interrupt
      exit_interrupt

    rescue

      if $error_message
        $error_message = $error_message + "\r\n" + "Error parsing #{file}." + "\r\n"
      else
        $error_message = "Error parsing #{file}."
      end # $error_message

    else
      timestamp = Time.at(parser.session.start_time).strftime('%Y/%m/%d %X')

      if $params['Start_date']
        scan_date = Date.parse(timestamp)
        # skip this file if it is not in the date range we want
        next if scan_date < $params['Start_date']
      end

      if $params['End_date']
        scan_date = Date.parse(timestamp)
        # skip this file if it is not in the date range we want
        next if scan_date > $params['End_date']
      end

      parser.hosts('up') do |host|

        host.getports(:any, 'open') do |port|
          next if (port.state == 'open|filtered') && (port.reason == 'no-response')
          foundmatch = false
          srv = port.service

          if srv.name
            portstring = srv.name
            portstring = portstring.downcase
            portstring.scan(service_string) { |match| foundmatch = true }
          end # srv.name

          if srv.product
            portstring = srv.product
            portstring = portstring.downcase
            portstring.scan(service_string) { |match| foundmatch = true }
          end # srv.product

          if srv.extra
            portstring = srv.extra
            portstring = portstring.downcase
            portstring.scan(service_string) { |match| foundmatch = true }
          end # srv.extra

          gen_output host, port, srv, timestamp if foundmatch 
          
          portstring = nil

        end  # host.getports(:any,"open")

      end  # parser.host..

      timestamp = nil

    end  # begin
  }

end  # service_search (service_string)

def os_search(os_string)

  foundmatch = nil
  host_os = nil

  if $params['Format_csv']
    if $reportfile
      $reportfile.puts 'IP address,hostname,os name,os family,os type,scan date'
    else
      puts 'IP address,hostname,os name,os family,os type,scan date'
    end
  end

  $listing.each { |file|
    begin
      parser = Nmap::Parser.parsefile(file)

    rescue Interrupt
      exit_interrupt

    rescue

      if $error_message
        $error_message = $error_message + "\r\n" + "Error parsing #{file}." + "\r\n"
      else
        $error_message = "Error parsing #{file}."
      end # $error_message

    else
      timestamp = Time.at(parser.session.start_time).strftime('%Y/%m/%d %X')

      if $params['Start_date']
        scan_date = Date.parse(timestamp)
        # skip this file if it is not in the date range we want
        next if scan_date < $params['Start_date']
      end

      if $params['End_date']
        scan_date = Date.parse(timestamp)
        # skip this file if it is not in the date range we want
        next if scan_date > $params['End_date']
      end

      parser.hosts('up') do |host|

        if $ip_filter
          next unless $ip_filter.include?(IPAddr.new(host.ip4_addr))
        end


        foundmatch = true
        host_os = host.os.name

        unless $params['All']

          foundmatch = false

          if host_os
            host_os = host_os.downcase
            foundmatch = true if host_os.include?(os_string)
          end # if host_os

        end

        # Special case: excluded OS will be dropped from --all hosts output
        if $params['Exclude_os']

          if host_os
            host_os = host_os.downcase
            foundmatch = false if host_os.include?($params['Exclude_os'])
          end
        end


        if foundmatch

          if $params['Format_bare']
            result_string = "#{host.addr}"
          elsif $params['Format_csv']
            result_string = "#{host.addr},#{host.hostname},\"#{host.os.name}\",\"#{host.os.osfamily}\",\"#{host.os.ostype}\",\"#{timestamp}\""
          else
            result_string = sprintf("%-15s %-40.40s %-30.30s %-12.12s %-17.17s %-19s", host.addr, host.hostname, host.os.name, host.os.osfamily, host.os.ostype, timestamp)
            # result_string = "#{host.addr}\t#{host.hostname}\t#{host.os.name}\t#{host.os.osfamily}\t#{host.os.ostype}\t#{timestamp}"
          end  # $params['Format_bare']


          # Write result to appropriate media
          if $reportfile
            $reportfile.puts result_string
          else
            puts result_string
          end # $reportfile

          result_string = nil

        end  # if foundmatch

      end  # parser.host..

      timestamp = nil

    end  # begin
  }  # $listing.each

end  # os_search(os_string)

def mac_search(mac_string)

  foundmatch      = nil
  host_mac        = nil
  host_mac_vendor = nil


  if $params['Format_csv']
    if $reportfile
      $reportfile.puts 'IP address,hostname,mac address,mac vendor,scan date'
    else
      puts 'IP address,hostname,mac address,mac vendor,scan date'
    end
  end

  $listing.each { |file|
    begin
      parser = Nmap::Parser.parsefile(file)

    rescue Interrupt
      exit_interrupt

    rescue

      if $error_message
        $error_message = $error_message + "\r\n" + "Error parsing #{file}." + "\r\n"
      else
        $error_message = "Error parsing #{file}."
      end # $error_message

    else
      timestamp = Time.at(parser.session.start_time).strftime('%Y/%m/%d %X')

      if $params['Start_date']
        scan_date = Date.parse(timestamp)
        # skip this file if it is not in the date range we want
        next if scan_date < $params['Start_date']
      end

      if $params['End_date']
        scan_date = Date.parse(timestamp)
        # skip this file if it is not in the date range we want
        next if scan_date > $params['End_date']
      end

      parser.hosts('up') do |host|

        if $ip_filter
          next unless $ip_filter.include?(IPAddr.new(host.ip4_addr))
        end

        foundmatch = false

        if host.mac_addr
          host_mac = host.mac_addr.upcase
          foundmatch = true if host_mac.downcase.include?(mac_string)
        end # if host_mac

        if host.mac_vendor
          host_mac_vendor = host.mac_vendor
          foundmatch = true if host_mac_vendor.downcase.include?(mac_string)
        end # if host_mac

        # Check the script data for the MAC from nbtstat.nse
        mac_regex = /NetBIOS MAC: (..:..:..:..:..:..) \((.*)\)/
        unless foundmatch
          host.scripts do |script|
            if script.id == 'nbstat'
              match = nil
              match = mac_regex.match(script.output)
              # script_result = script.output.downcase
              if match
                host_mac = match[1].upcase if match[1]
                host_mac_vendor = match[2] if match[2]
                foundmatch = true
              end
            end
          end  # host.scripts do |script|
        end # !foundmatch

        # Special case: excluded OS will be dropped from --all hosts output
        if $params['Exclude_os']

          if host_os
            host_os = host_os.downcase
            foundmatch = false if host_os.include?($params['Exclude_os'])
          end
        end


        if foundmatch

          if $params['Format_bare']
            result_string = "#{host.addr}"
          elsif $params['Format_csv']
            result_string = "#{host.addr},#{host.hostname},\"#{host_mac}\",\"#{host_mac_vendor}\",\"#{timestamp}\""
          else
            result_string = sprintf('%-15s %-40.40s %-17.17s %-20.20s %-19s', host.addr, host.hostname, host_mac, host_mac_vendor, timestamp)
          end  # $params['Format_bare']

          # Write result to appropriate media
          if $reportfile
            $reportfile.puts result_string
          else
            puts result_string
          end # $reportfile

          result_string = nil

        end  # if foundmatch

      end  # parser.host..

      timestamp = nil

    end  # begin
  }  # $listing.each

end  # mac_search(mac_string)

def script_search(script_string)

  puts
  if $params['Format_csv']
    puts 'IP address,hostname,port,service,product,version,extra info,script name,scan date'
  end

  $listing.each { |file|

    begin
      parser = Nmap::Parser.parsefile(file)

    rescue Interrupt
      exit_interrupt

    rescue

      if $error_message
        $error_message = $error_message + "\r\n" + "Error parsing #{file}." + "\r\n"
      else
        $error_message = "Error parsing #{file}."
      end # $error_message

    else
      timestamp = Time.at(parser.session.start_time).strftime('%Y/%m/%d %X')

      if $params['Start_date']
        scan_date = Date.parse(timestamp)
        # skip this file if it is not in the date range we want
        next if scan_date < $params['Start_date']
      end

      if $params['End_date']
        scan_date = Date.parse(timestamp)
        # skip this file if it is not in the date range we want
        next if scan_date > $params['End_date']
      end

      parser.hosts('up') do |host|

        if $ip_filter
          next unless $ip_filter.include?(IPAddr.new(host.ip4_addr))
        end


        # Changes to deal with host level scripts
        host.scripts do |script|
          script_result = script.output.downcase
          if (script_result.include? script_string) || (script.id.include? script_string)
            gen_output host, '', '', timestamp, script
          end
        end  # port.scripts do |script|



        host.getports(:any, 'open') do |port|
          next if (port.state == 'open|filtered') && (port.reason == 'no-response')
          srv = port.service

          port.scripts do |script|
            script_result = script.output.downcase
            if (script_result.include? script_string) || (script.id.include? script_string)
              gen_output host, port, srv, timestamp, script
            end
          end  # port.scripts do |script|

        end  # host.getports(:any,"open")

      end  # parser.host..

      timestamp = nil

    end  # begin
  }

end  # script_search (script_string)

def statistics(counter)

  port_stats       = Hash.new(0)
  os_stats         = Hash.new(0)
  service_stats    = Hash.new(0)
  product_stats    = Hash.new(0)
  mac_vendor_stats = Hash.new(0)
  host_counter     = 0

  $listing.each { |file|

    begin
      parser = Nmap::Parser.parsefile(file)

    rescue Interrupt
      exit_interrupt

    rescue

      if $error_message
        $error_message = $error_message + "\r\n" + "Error parsing #{file}." + "\r\n"
      else
        $error_message = "Error parsing #{file}."
      end # $error_message

    else

      timestamp = Time.at(parser.session.start_time).strftime('%Y/%m/%d %X')

      if $params['Start_date']
        scan_date = Date.parse(timestamp)
        # skip this file if it is not in the date range we want
        next if scan_date < $params['Start_date']
      end

      if $params['End_date']
        scan_date = Date.parse(timestamp)
        # skip this file if it is not in the date range we want
        next if scan_date > $params['End_date']
      end


      parser.hosts('up') do |host|

        if $ip_filter
          if !$ip_filter.include?(IPAddr.new(host.ip4_addr))
            next
          end
        end

        # Allow output to be limited to just certain Oses
        if $params['OS']
          host_os = host.os.name
          if host_os
            host_os = host_os.downcase
            next unless host_os.include?($params['OS'])
          else
            next
          end # if host_os
        end

        host_counter = host_counter + 1

        mac_vendor_stats["#{host.mac_vendor}"] += 1
        
        # Increment OS stats counter by 1
        os_stats["#{host.os.name}"] += 1


        host.getports(:any, 'open') do |port|
          next if (port.state == 'open|filtered') && (port.reason == 'no-response')

          # Develop stats on ports
          port_stats["#{port.num}/#{port.proto}"] += 1

          # Develop stats on port service field
          service_stats["#{port.service.name}"] += 1

          # Develop stats on port service product field
          product_stats["#{port.service.product}"]+= 1

        end  # host.getports(:any,"open") do |port|

      end # parser.hosts('up') do |host|

    end

  }

  puts
  puts "The specified subset of logs contain information on #{host_counter} hosts."
  puts
  puts 'OS statistics:'
  puts
  puts 'Count  OS'
  # Reverse sort the hash table (thats the -1 part), then iterate through
  # the temporary array and display the results.

  os_stats.sort { |a, b| -1 * (a[1] <=> b[1]) }.each_with_index { |item, index|
    break if counter && index.to_i == counter
    puts sprintf('%5d  %s ', item[1], item[0])
  }

  puts
  puts 'Port statistics:'
  puts
  puts 'Count  Port'
  # Reverse sort the hash table (thats the -1 part), then iterate through
  # the temporary array and display the results.

  port_stats.sort { |a, b| -1 * (a[1] <=> b[1]) }.each_with_index { |item, index|
    break if counter && index.to_i == counter
    puts sprintf('%5d  %s ', item[1], item[0])
  }


  puts
  puts 'Service statistics:'
  puts
  puts 'Count  Service'
  # Reverse sort the hash table (thats the -1 part), then iterate through
  # the temporary array and display the results.

  service_stats.sort { |a, b| -1 * (a[1] <=> b[1]) }.each_with_index { |item, index|
    break if counter && index.to_i == counter
    puts sprintf('%5d  %s ', item[1], item[0])
  }

  puts
  puts 'Product statistics:'
  puts
  puts 'Count  Product'
  # Reverse sort the hash table (thats the -1 part), then iterate through
  # the temporary array and display the results.

  product_stats.sort { |a, b| -1 * (a[1] <=> b[1]) }.each_with_index { |item, index|
    break if counter && index.to_i == counter
    puts sprintf('%5d  %s ', item[1], item[0])
  }

  puts
  puts 'MAC Vendor statistics:'
  puts
  puts 'Count  Vendor'
  mac_vendor_stats.sort { |a, b| -1 * (a[1] <=> b[1]) }.each_with_index { |item, index|
    break if counter && index.to_i == counter
    puts sprintf('%5d  %s ', item[1], item[0])
  }

  puts
  puts

end # statistics
}
