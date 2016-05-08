#!/usr/bin/env ruby
#
#  cert-query.rb
#
#  Searches nmap XML output for ssl related port, service, script output
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

PROG_VERSION = '0.98.02'

require 'nmap/parser'
require 'optparse'
require 'ipaddr'
require 'date'

$log_path = './logs'

$ip_filter = nil
$reportfile = nil
$Results = Array.new
$starttime = Time.now
$now = Date.parse(Time.now.strftime('%Y/%m/%d %X'))

begin
  $error_message = nil
  $params = ParseArgs.parse(ARGV)

  # Set the XML location to the default if one is not specified on the command line
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

  if $params['Port']

    puts
    port_search $params['Port']

    # Exit cleanly
    exit_normal

  end

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

    legal_option = false
    options['Cert_Search'] = false

    opts = OptionParser.new do |opts|
      opts.banner = 'Usage: cert-query.rb [options]'

      opts.separator ''
      opts.separator 'Query options:'

      opts.on('-p', '--port <number>', 'Search for specified port number') do |p|
        options['Port'] = p.to_i
        legal_option = true
      end

      opts.on('-k', '--key-size <number>', 'Search for TLS certs with a specific key size.') do |k|
        options['Key'] = k.to_i
        options['Cert_Search'] = true
      end

      opts.on('--key-max <number>', 'Search for TLS certs with the specified size or SMALLER') do |key_max|
        options['KeyMax'] = key_max.to_i
        options['Cert_Search'] = true
      end

      opts.on('--key-min <number>', 'Search for TLS certs with the specified size or LARGER') do |key_min|
        options['KeyMin'] = key_min.to_i
        options['Cert_Search'] = true
      end

      opts.on('--key-type <string>', 'Search for TLS certs with the specified key type (RSA/ECDSA/DSA)') do |s|
        options['KeyType'] = s.downcase
        options['Cert_Search'] = true
      end

      opts.on('--cert-expired', 'Show only services where the TLS certificate has expired.') do
        options['cert_expired'] = true
        options['Cert_Search'] = true
      end

      opts.on('-s', '--service <string>', '*Search service, product and information fields for the specified string') do |s|
        options['Service'] = s.downcase
        legal_option = true
      end

      opts.on('-o', '--operating-system <string>', 'Search for specified OS string') do |o|
        options['OS'] = o.downcase
        legal_option = true
      end

      opts.on('--sig-algo <string>', 'Search for TLS certs signed with a certain signature algorithm') do |sig_algo|
        options['Sigalgo'] = sig_algo.to_s.downcase
        options['Cert_Search'] = true
      end

      opts.on('--all-ports', 'Return a list of all open ports in the logs') do
        options['All_Ports'] = true
        options['Port'] = 'all'
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
        if (start_date.to_s =~ /^\d{4}[.\/-]\d{1,2}[.\/-]\d{1,2}$/)
          options['Start_date'] = Date.parse($&)
        else
          puts
          puts 'Error: Option passed for start date does not appear valid. Use -h to see valid formats.'
          puts
          exit
        end
      end

      opts.on('--end-date <YYYY-MM-DD>', 'Limit output to hosts scanned ON or BEFORE the specified date, valid delimiters are . / and -') do |end_date|
        if (end_date.to_s =~ /^\d{4}[.\/-]\d{1,2}[.\/-]\d{1,2}$/)
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

      opts.on('-x', '--exclude-service <string>', '*Exclude service where the service name or product matches the specified string') do |x|
        options['Exclude'] = x.downcase
      end

      opts.on('--exclude-os <string>', 'Exclude results matching the specified OS (if the OS is identified by Nmap)') do |exclude_os|
        options['Exclude_os'] = exclude_os.downcase
      end



      opts.separator ''
      opts.separator 'Misc options:'

      opts.on('-l', '--log <location>', '*Specify a particular Nmap XML file or the location of the directory containing Nmap XML logs') do |l|
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

      opts.on('-r', '--report <filename>', '*Output results to specified file, as opposed to the terminal') do |r|
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

      opts.on('-c', '--csv', '*Output results in CSV format') do
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
        puts "\tcert-query #{Prog_version} by Tom Sellers"
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

    if !legal_option
      options['All_Ports'] = true
      options['Port'] = 'all'
      legal_option = true
    end #!legal_option

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

class SSLPort

  attr_reader :addr, :hostname, :num, :proto
  attr_reader :tunnel, :svcname, :svcversion, :svcproduct, :timestamp
  attr_reader :expire, :created, :type, :bits, :issuer, :subject
  attr_reader :sigalgo, :thumbprint

  # This depends on the current format of the ssl-cert.nse nmap script
  def initialize(host, ssl_port, timestamp)

    @addr         = host.addr
    @hostname     = host.hostname
    @num          = ssl_port.num.to_i
    @proto        = ssl_port.proto
    @tunnel       = ssl_port.service.tunnel
    @svcname      = ssl_port.service.name
    @svcproduct   = ssl_port.service.product
    @svcversion   = ssl_port.service.version
    @timestamp    = timestamp

    if ssl_port.script('ssl-cert') && ssl_port.script('ssl-cert').output
      expire_regex = /Not valid after:  (\d{4}-\d{2}-\d{2}T\d\d:\d\d:\d\d)/
      match = expire_regex.match(ssl_port.script('ssl-cert').output)
      @expire = Date.parse(match[1]) if match

      created_regex = /Not valid before: (\d{4}-\d{2}-\d{2}T\d\d:\d\d:\d\d)/
      match = created_regex.match(ssl_port.script('ssl-cert').output)
      @created = Date.parse(match[1]) if match

      type_regex = /Public Key type: (\w{1,5})/
      match = type_regex.match(ssl_port.script('ssl-cert').output)
      @type = match[1].upcase if match

      bits_regex = /Public Key bits: (\w{1,5})/
      match = bits_regex.match(ssl_port.script('ssl-cert').output)
      @bits = match[1].to_i if match

      issuer_regex = /Issuer: commonName=([^\/\n]*)/
      match = issuer_regex.match(ssl_port.script('ssl-cert').output)
      @issuer = match[1] if match

      subject_regex = /Subject: commonName=([^\/\n]*)/
      match = subject_regex.match(ssl_port.script('ssl-cert').output)
      @subject = match[1] if match

      sigalgo_regex = /Signature Algorithm: ([^\n]*)/
      match = sigalgo_regex.match(ssl_port.script('ssl-cert').output)
      @sigalgo = match[1] if match

      thumbprint_regex = /SHA-1:([^\n]*)/
      match = thumbprint_regex.match(ssl_port.script('ssl-cert').output)
      @thumbprint = match[1] if match


    end

  end

end

def gen_output

  counter = 0

  if $reportfile
    $reportfile.puts 'IP address,hostname,port,service,product,version,bits,type,issued,expires,subject,issuer,scan date'
  elsif !$params['Format_bare'] 
    puts 'IP address,hostname,port,service,product,version,bits,type,issued,expires,subject,issuer,sigalgo,scan date'
  end


  $Results.sort { |a, b| 1*(a.addr <=> b.addr)}.each { |port|

    # Add conditional code here
    counter += 1
    if $params['Format_bare']
      puts port.addr
    else
      puts "#{port.addr},#{port.hostname},#{port.num}/#{port.proto},#{port.tunnel}/#{port.svcname},\"#{port.svcproduct}\",\"#{port.svcversion}\",#{port.bits},#{port.type},#{port.created},#{port.expire},\"#{port.subject}\",\"#{port.issuer}\",#{port.sigalgo},#{port.timestamp}"
    end
  }

  unless $params['Format_bare']
    puts "\r\nTotal output hosts:  #{counter}"
    endtime = Time.now - $starttime
    puts "Runtime #{endtime}"
  end

end

def port_search(port_num)

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
      timestamp = Time.at(parser.session.start_time).strftime('%Y/%m/%d %X')

      if $params['Start_date']
        scan_date = Date.parse(timestamp)
        next if scan_date < $params['Start_date']
      end

      if $params['End_date']
        scan_date = Date.parse(timestamp)
        next if scan_date > $params['End_date']
      end


      parser.hosts('up') do |host|

        # Host level filtering here
        if $ip_filter
          next unless $ip_filter.include?(IPAddr.new(host.ip4_addr))
        end

        if host.os.name
          if $params['Exclude_os']
            next if host.os.name.downcase.include?($params['Exclude_os'])
          end

          if $params['OS']
            next unless host.os.name.downcase.include?($params['OS'])
          end
        end

        host.getports(:any, 'open') do |port|
          next unless (port.num == port_num || $params['All_Ports'])
          next if (port.state == 'open|filtered') && (port.reason == 'no-response')

          # Port level filtering here
          if $params['Exclude_port']
            if port.num
              next if port.num == $params['Exclude_port']
            end
          end


          if port.service.tunnel == 'ssl'

            # Service string matching for INCLUSION or EXCLUSION in result set
            if $params['Service'] || $params['Exclude']

              port_string = nil

              if port.service.name
                port_string = port.service.name
              end

              if port.service.tunnel
                port_string = port.service.tunnel + '/' + port_string
              end

              # Use the same benchmark as nmap (name_confidence in portlist.cc)
              # to determine the need for the ? on the end of the service name
              if port.service.confidence && port.service.confidence <= 5
                port_string = port_string + '?'
              end

              if port.service.product
                port_string += ' ' + port.service.product
              end

              if port.service.version
                port_string += ' ' + port.service.version
              end

              if port.service.extra
                port_string += ' ' + port.service.extra
              end

              port_string = port_string.downcase

              if $params['Service']
                foundmatch = false
                port_string.scan($params['Service']) { |match| foundmatch = true }
                next unless foundmatch
              end

              if $params['Exclude']
                foundmatch = false
                port_string.scan($params['Exclude']) { |match| foundmatch = true }
                next if foundmatch
              end

            end

            if port.script('ssl-cert')
              ssl_service = SSLPort.new(host, port, timestamp)

              # SSL level filtering here
              if $params['Cert_Search']

                # Key bits filtering
                if ssl_service.bits
                  if $params['Key']
                    next unless ssl_service.bits == $params['Key']
                  end

                  if $params['KeyMax']
                    next if ssl_service.bits > $params['KeyMax']
                  end

                  if $params['KeyMin']
                    next if ssl_service.bits < $params['KeyMin']
                  end
                end

                if $params['KeyType']
                  if ssl_service.type
                    next unless ssl_service.type.downcase == $params['KeyType']
                  end
                end

                # Cert date filtering
                if $params['cert_expired']
                  if ssl_service.expire
                    next unless ssl_service.expire < $now
                  end
                end

                # Signature algo filtering
                if $params['Sigalgo']
                  if ssl_service.sigalgo
                    next unless ssl_service.sigalgo.downcase == $params['Sigalgo']
                  end
                end

              end # $params['Cert_Search']

              # Report anything that makes it this far
              $Results.push(ssl_service)

            else
              # Build out a valid object for services without certificate data
              unless $params['Cert_Search']
                ssl_service = SSLPort.new(host, port, timestamp)
                $Results.push(ssl_service)
              end
            end # port.script...

          end

        end  # host.getports

      end  # parser.host..

      timestamp = nil
    end  # begin
  }

  if $params['Metrics']
    statistics
  else
    gen_output
  end

end # port_search

def statistics

  counter = $params['Metric_counter'] if $params['Metric_counter']

  port_stats     = Hash.new(0)
  service_stats  = Hash.new(0)
  bits_stats     = Hash.new(0)
  product_stats  = Hash.new(0)
  sigalgo_stats  = Hash.new(0)
  type_stats     = Hash.new(0)
  issuer_stats   = Hash.new(0)
  subject_stats  = Hash.new(0)
  thumbprint_stats = Hash.new(0)
  thumbprint_subject = Hash.new(0)
  host_counter   = 0

  $Results.each { |port|

    host_counter = host_counter + 1

    port_stats["#{port.num}/#{port.proto}"]  += 1 # if port.num && port.proto
    service_stats["#{port.svcname}"]         += 1 # if port.svcname
    product_stats["#{port.svcproduct}"]      += 1 # if port.svcproduct
    bits_stats["#{port.bits}"]               += 1 # if port.bits
    sigalgo_stats["#{port.sigalgo}"]         += 1 # if port.sigalgo
    issuer_stats["#{port.issuer}"]           += 1 # if port.issuer
    subject_stats["#{port.subject}"]         += 1 # if port.subject
    type_stats["#{port.type}"]               += 1 # if port.type
    thumbprint_stats["#{port.thumbprint}"]  += 1 # if port.thumbprint
    if thumbprint_stats["#{port.thumbprint}"] > 1
      thumbprint_subject["#{port.thumbprint}"] = port.subject
    end
  }

  puts
  puts "The specified subset of logs contain information on #{host_counter} hosts."

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
  service_stats.sort { |a, b| -1 * (a[1] <=> b[1]) }.each_with_index { |item, index|
    break if counter && index.to_i == counter
    puts sprintf('%5d  %s ', item[1], item[0])
  }

  puts
  puts 'Product statistics:'
  puts
  puts 'Count  Product'
  product_stats.sort { |a, b| -1 * (a[1] <=> b[1]) }.each_with_index { |item, index|
    break if counter && index.to_i == counter
    puts sprintf('%5d  %s ', item[1], item[0])
  }

  puts
  puts 'Bit strength statistics:'
  puts
  puts 'Count  Bits'
  bits_stats.sort { |a, b| -1 * (a[1] <=> b[1]) }.each_with_index { |item, index|
    break if counter && index.to_i == counter
    puts sprintf('%5d  %s ', item[1], item[0])
  }
    
  puts
  puts 'Signature Algorithm statistics:'
  puts
  puts 'Count  Signature Algorithm'
  sigalgo_stats.sort { |a, b| -1 * (a[1] <=> b[1]) }.each_with_index { |item, index|
    break if counter && index.to_i == counter
    puts sprintf('%5d  %s ', item[1], item[0])
  }

  puts
  puts 'Issuer statistics:'
  puts
  puts 'Count  Issuer'
  issuer_stats.sort { |a, b| -1 * (a[1] <=> b[1]) }.each_with_index { |item, index|
    break if counter && index.to_i == counter
    puts sprintf('%5d  %s ', item[1], item[0])
  }
 
  puts
  puts 'Subject statistics:'
  puts
  puts 'Count  Subject'
  subject_stats.sort { |a, b| -1 * (a[1] <=> b[1]) }.each_with_index { |item, index|
    break if counter && index.to_i == counter
    puts sprintf('%5d  %s ', item[1], item[0])
  }

  puts
  puts 'Certificate type statistics:'
  puts
  puts 'Count  Type'
  type_stats.sort { |a, b| -1 * (a[1] <=> b[1]) }.each_with_index { |item, index|
    break if counter && index.to_i == counter
    puts sprintf('%5d  %s ', item[1], item[0])
  }

  puts
  puts 'Thumbprint statistics:'
  puts
  puts 'Count  Thumbprint'
  thumbprint_stats.sort { |a, b| -1 * (a[1] <=> b[1]) }.each_with_index { |item, index|
    break if counter && index.to_i == counter
    puts sprintf('%5d  %s  %s', item[1], item[0], thumbprint_subject[item[0]])
  }

  puts
  puts

end # statistics

}
