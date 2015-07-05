#!/usr/bin/env ruby
#
#  util-checkhost.rb
#
#  utility to move nmap XML files containing 0 hosts to a backup directory
#  and out of the logs directory.  Speeds query processes of both fathom.rb
#  and fp-list.rb
#
#  Part of the Fathom suite written by Tom Sellers <fathom_at_fadedcode.net>
#
#  Requires:
#                               Ruby (1.9.1 recommended)
#
#                               Kris Katterjohn's Ruby Nmap::Parser
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

$target_file = nil


$backup = "./logs/backup"
$params = ParseArgs.parse(ARGV)
$target_path = "./logs/" + $target_file

listing = Dir.glob($target_path)

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
                        puts "   Moving #{filepath}, #{parser.hosts("up").count} hosts in this file group."
                        FileUtils.mv Dir.glob(filepath), $backup
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

                        opts.on("--filename 10.10.10.10.xml", "Select files containing certain IP Addresses") do |file_name|
                        $target_file = file_name.to_s
                        legal_option = true
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


