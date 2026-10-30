# frozen_string_literal: true

describe AuthProto::PAR::Request do
  let(:config) do
    AuthProto::PAR::Request::Configuration.new.tap do |c|
      c.client_id = "client123"
      c.redirect_uri = "https://example.com/callback"
      c.code_challenge = "abc123"
      c.state = "xyz456"
      c.scope = "atproto read"
    end
  end

  describe ".build" do
    it "should create a new request instance" do
      request = AuthProto::PAR::Request.build do |c|
        c.client_id = "client123"
        c.redirect_uri = "https://example.com/callback"
        c.code_challenge = "abc123"
        c.state = "xyz456"
        c.scope = "atproto read"
      end

      request.should be_an_instance_of(AuthProto::PAR::Request)
      request.client_id.should == "client123"
      request.redirect_uri.should == "https://example.com/callback"
    end
  end

  describe "#initialize" do
    it "should initialize with valid configuration" do
      request = AuthProto::PAR::Request.new(config)
      request.client_id.should == "client123"
      request.redirect_uri.should == "https://example.com/callback"
      request.code_challenge.should == "abc123"
      request.state.should == "xyz456"
      request.scope.should == "atproto read"
    end

    it "should raise an error if a required parameter is missing" do
      config.client_id = nil
      expect {
        AuthProto::PAR::Request.new(config)
      }.to raise_error(AuthProto::PAR::Error)
    end

    it "should set response_type and code_challenge_method internally" do
      request = described_class.new(config)
      form = URI.decode_www_form(request.to_form).to_h
      form['response_type'].should == 'code'
      form['code_challenge_method'].should == 'S256'
      config.should_not respond_to(:response_type=)
      config.should_not respond_to(:code_challenge_method=)
      request.should_not respond_to(:response_type=)
      request.should_not respond_to(:code_challenge_method=)
    end

    it "should raise an error if atproto scope is missing" do
      config.scope = "read"
      expect {
        AuthProto::PAR::Request.new(config)
      }.to raise_error(AuthProto::PAR::Error)
    end
  end

  describe "#to_form" do
    it "should return form-encoded parameters" do
      request = AuthProto::PAR::Request.new(config)
      form = request.to_form
      form.should include("response_type=code")
      form.should include("client_id=client123")
      form.should include("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback")
      form.should include("code_challenge=abc123")
      form.should include("code_challenge_method=S256")
      form.should include("state=xyz456")
      form.should include("scope=atproto+read")
    end
  end
end
