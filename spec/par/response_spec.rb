# frozen_string_literal: true

describe AuthProto::PAR::Response do
  describe "#initialize" do
    it "should initialize with valid parameters" do
      response = AuthProto::PAR::Response.new(request_uri: "https://example.com/request", expires_in: 3600)
      response.request_uri.should == "https://example.com/request"
      response.expires_in.should == 3600
    end

    it "should raise an error if request_uri is missing" do
      expect {
        AuthProto::PAR::Response.new(request_uri: nil, expires_in: 3600)
      }.to raise_error(AuthProto::PAR::Error)
    end

    it "should raise an error if request_uri is empty" do
      expect {
        AuthProto::PAR::Response.new(request_uri: "", expires_in: 3600)
      }.to raise_error(AuthProto::PAR::Error)
    end

    it "should raise an error if expires_in is not positive" do
      expect {
        AuthProto::PAR::Response.new(request_uri: "https://example.com/request", expires_in: 0)
      }.to raise_error(AuthProto::PAR::Error)
    end

    ['90', '0', '-90', 'invalid', nil, 0.5, 1.5, 90.0, -1, true, [], {}].each do |expires_in|
      it "should reject an expiry that is not a positive integer: #{expires_in.inspect}" do
        expect {
          AuthProto::PAR::Response.new(request_uri: 'https://example.com/request', expires_in: expires_in)
        }.to raise_error(AuthProto::PAR::Error, "expires_in must be a positive integer")
      end
    end

    [[], ['uri'], {}, 90, true].each do |request_uri|
      it "should reject a request URI that is not a string: #{request_uri.inspect}" do
        expect {
          AuthProto::PAR::Response.new(request_uri: request_uri, expires_in: 90)
        }.to raise_error(AuthProto::PAR::Error, "request_uri must be a nonempty string")
      end
    end
  end
end
