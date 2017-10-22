require "set"

# @author Nicholas Sardo

module LogParser
  extend self
  # Parses each line of log file searching for potential hacker IP's
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
  def parse_lines( file : String, num_lines : Number ) : Array(String)
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
    p suspects.to_a
  end
end

#LogParser.parse_lines "/users/nsardo/desktop/log-file-source/auth.log", 100
