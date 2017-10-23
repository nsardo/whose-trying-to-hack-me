require "set"
include IO

# @author Nicholas Sardo

module LogParser
  extend self
  # Parses each line of auth.log file searching for potential hacker IP's
  #
  # ```
  # parse_lines "/var/log/auth.log", 100
  # ```
  #
  # Above produces a result similar to:
  #
  # ```
  # ["182.254.146.248",
  # "74.215.81.152",
  # "51.255.46.112",
  # "139.199.109.233",
  # "123.164.227.204"]
  # ```
  #
  def parse_auth( file : String, num_lines : Number ) : Array(String)
    count = 0
    suspects = Set(String).new
    File.each_line(file) do |line|
      count += 1
      if count < num_lines
        w = line.split(" ")
        if w[5] == "Invalid"
          suspects.add( w[-1] )
        end
      end
    end
    io     = IO::Memory.new(50)
    ar     = [] of String
    outp_a = [] of String
    ar     = suspects.to_a

    ar.each do |a|
      puts "\n"
      puts a
      cmd = "whois #{a} | grep 'NetRange:\\|NetType:\\|OrgName:\\|Comment:\\|Address:\\|City:\\|StateProv:\\|PostalCode:\\|Country:'"
      io << (Process.run(cmd, shell: true, output: io, error: io))
      io.rewind
      outp_a = io.to_s.split("\n")
      p "-------------------------------------------"
      outp_a.each do |l|
        next if l =~ /^#/
        p l
      end
      p "-------------------------------------------"
      io.clear
    end
    p ar
  end
end
# p $?.exitstatus

LogParser.parse_auth "/users/nsardo/desktop/log-file-source/auth.log", 100
