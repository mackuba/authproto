# frozen_string_literal: true

require 'net/http'
require 'openssl'
require 'resolv'

describe AuthProto::HTTPClient do
  let(:client) { AuthProto::HTTPClient.new }
  let(:sample_url) { "https://example.com/resource" }
  let(:private_ip) { "192.168.1.1" }

  before do
    Resolv::DNS.any_instance.stubs(:getaddresses).returns([Resolv::IPv4.create("93.184.216.34")])
  end

  describe "request validation" do
    it "should reject non-HTTPS URLs" do
      expect {
        client.get("http://example.com")
      }.to raise_error(AuthProto::HTTPClient::SSRFError)
    end

    it "should reject URLs with fragments" do
      expect {
        client.get("https://example.com#fragment")
      }.to raise_error(AuthProto::HTTPClient::SSRFError)
    end

    it "should reject URLs without hosts" do
      expect {
        client.get("https:///resource")
      }.to raise_error(AuthProto::HTTPClient::SSRFError)
    end

    it "should reject private network IPs" do
      stub_request(:get, "https://#{private_ip}/")
        .to_return(status: 200, body: "")

      expect {
        client.get("https://#{private_ip}/")
      }.to raise_error(AuthProto::HTTPClient::SSRFError)
    end

    it "should reject loopback and IPv4-mapped IPv6 addresses" do
      %w[127.0.0.1 127.10.20.30 [::1] [::ffff:127.0.0.1]].each do |host|
        expect { client.get("https://#{host}/") }.to raise_error(AuthProto::HTTPClient::SSRFError)
      end
    end

    it "should reject hostnames resolving to any forbidden address" do
      Resolv::DNS.any_instance.stubs(:getaddresses).returns([
                                                              Resolv::IPv4.create("93.184.216.34"), Resolv::IPv6.create("::1")
                                                            ])
      expect { client.get(sample_url) }.to raise_error(AuthProto::HTTPClient::SSRFError)
    end

    it "should reject hostnames without resolved addresses" do
      Resolv::DNS.any_instance.stubs(:getaddresses).returns([])
      expect { client.get(sample_url) }.to raise_error(AuthProto::HTTPClient::SSRFError)
    end
  end

  describe "#get" do
    before do
      stub_request(:get, sample_url)
        .to_return(status: 200, body: "success", headers: { "Content-Type" => "text/plain" })
    end

    it "should make successful GET requests" do
      response = client.get(sample_url)
      response[:status].should == 200
      response[:body].should == "success"
    end

    it "should include security headers" do
      stub_request(:get, sample_url)
        .with(headers: { "Cache-Control" => "no-store" })
        .to_return(status: 200, body: "")

      client.get(sample_url)
      WebMock.should have_requested(:get, sample_url).with(headers: { "Cache-Control" => "no-store" })
    end

    it "should forward user headers" do
      custom_headers = { "X-Custom" => "value" }

      stub_request(:get, sample_url)
        .with(headers: custom_headers)
        .to_return(status: 200, body: "")

      client.get(sample_url, custom_headers)
      WebMock.should have_requested(:get, sample_url).with(headers: custom_headers)
    end

    it "should follow redirects up to limit" do
      redirect_url = "https://example.com/final"

      stub_request(:get, sample_url)
        .to_return(status: 302, headers: { "Location" => redirect_url })
      stub_request(:get, redirect_url)
        .to_return(status: 200, body: "redirected")

      response = client.get(sample_url)
      response[:body].should == "redirected"
    end

    it "should return the initial response when redirects are disabled for a request" do
      target = "https://example.com/final"
      stub_request(:get, sample_url).with(headers: { "X-Custom" => "value" })
        .to_return(status: 302, headers: { "Location" => target }, body: "redirect")
      stub_request(:get, target).to_return(status: 200, body: "followed")

      response = client.get(sample_url, { "X-Custom" => "value" }, follow_redirects: false)

      response[:status].should == 302
      response[:headers]["location"].should == target
      response[:body].should == "redirect"
      WebMock.should_not have_requested(:get, target)
    end

    it "should still enforce response size limits when redirects are disabled" do
      stub_request(:get, sample_url).to_return(status: 302, headers: {
        "Location" => "https://example.com/final",
        "Content-Length" => (AuthProto::HTTPClient::MAX_RESPONSE_SIZE + 1).to_s
      })

      expect { client.get(sample_url, follow_redirects: false) }.to raise_error(AuthProto::HTTPClient::HTTPError)
    end

    it "should prevent redirect loops" do
      stub_request(:get, sample_url)
        .to_return(status: 302, headers: { "Location" => sample_url })

      expect {
        client.get(sample_url)
      }.to raise_error(AuthProto::HTTPClient::HTTPError)
    end

    it "should reject oversized responses" do
      large_response = "x" * (AuthProto::HTTPClient::MAX_RESPONSE_SIZE + 1)

      stub_request(:get, sample_url)
        .to_return(status: 200, body: large_response)

      expect {
        client.get(sample_url)
      }.to raise_error(AuthProto::HTTPClient::HTTPError)
    end
  end

  describe "#post" do
    let(:post_body) { "request body" }
    let(:post_headers) { { "Content-Type" => "text/plain" } }

    before do
      stub_request(:post, sample_url)
        .to_return(status: 201, body: "created")
    end

    it "should make successful POST requests" do
      response = client.post(sample_url, body: post_body, headers: post_headers)
      response[:status].should == 201
      response[:body].should == "created"
    end

    it "should send request body" do
      stub_request(:post, sample_url)
        .with(body: post_body)
        .to_return(status: 201)

      client.post(sample_url, body: post_body)
      WebMock.should have_requested(:post, sample_url).with(body: post_body)
    end

    it "should handle POST redirects" do
      redirect_url = "https://example.com/final"

      stub_request(:post, sample_url)
        .with(body: post_body)
        .to_return(status: 307, headers: { "Location" => redirect_url })
      stub_request(:post, redirect_url)
        .with(body: post_body)
        .to_return(status: 201, body: "redirected")

      response = client.post(sample_url, body: post_body)
      response[:body].should == "redirected"
      WebMock.should have_requested(:post, redirect_url).with(body: post_body)
    end
    #
    # it "should handle POST redirects" do
    #   redirect_url = "https://example.com/final"
    #
    #   stub_request(:post, sample_url).
    #     to_return(status: 307, headers: {"Location" => redirect_url})
    #   stub_request(:post, redirect_url).
    #     to_return(status: 201, body: "redirected")
    #
    #   response = client.post(sample_url, body: post_body)
    #   response[:body].should == "redirected"
    #   WebMock.should have_requested(:post, redirect_url)
    # end

    it "should include security headers in POST requests" do
      stub_request(:post, sample_url)
        .with(headers: { "Cache-Control" => "no-store" })
        .to_return(status: 201)

      client.post(sample_url)
      WebMock.should have_requested(:post, sample_url).with(headers: { "Cache-Control" => "no-store" })
    end
  end

  describe "timeout handling" do
    let(:client) { AuthProto::HTTPClient.new(timeout: 1) }

    it "should handle read timeouts" do
      stub_request(:get, sample_url).to_timeout

      expect {
        client.get(sample_url)
      }.to raise_error(AuthProto::HTTPClient::HTTPError)
    end
  end

  describe "SSL verification" do
    it "should verify SSL certificates by default" do
      client = AuthProto::HTTPClient.new
      http = Net::HTTP.new("example.com")
      client.send(:configure_http_client, http)
      http.verify_mode.should == OpenSSL::SSL::VERIFY_PEER
    end

    it "should be able to disable SSL verification" do
      client = AuthProto::HTTPClient.new(verify_ssl: false)
      http = Net::HTTP.new("example.com")
      client.send(:configure_http_client, http)
      http.verify_mode.should == OpenSSL::SSL::VERIFY_NONE
    end
  end
end
