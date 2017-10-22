require "spec"
require "../src/logparser"

#initial test hard-coded to test files on dev computer for moment
describe LogParser do
  describe "#parse_auth" do
    it "should return an array of IP's" do
      LogParser.parse_auth("/users/nsardo/desktop/log-file-source/auth.log",
        100).should eq ["182.254.146.248",
 "74.215.81.152",
 "51.255.46.112",
 "103.240.8.244",
 "104.131.30.247",
 "139.199.109.233",
 "168.0.114.130",
 "120.61.177.61",
 "123.164.227.204"]
    end
  end
end
