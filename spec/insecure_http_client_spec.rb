# frozen_string_literal: true

require 'json'
require 'net/http'
require 'openssl'
require 'resolv'

describe AuthProto::InsecureHTTPClient do
  let(:client) { AuthProto::InsecureHTTPClient.new }

  it "should support GET and POST over HTTP and HTTPS at public and local destinations" do
    urls = %w[
      http://localhost:9292/test http://127.0.0.1:9292/test http://[::1]:9292/test
      http://192.168.1.1/test http://dev.example.com/test https://plc.directory/test https://127.0.0.1:9292/test
    ]
    urls.each do |url|
      stub_request(:get, url).with(headers: { "Cache-Control" => "no-store" })
                             .to_return(status: 200, body: "ok")
      stub_request(:post, url).with(body: "test=value", headers: { "X-Test" => "yes" })
                              .to_return(status: 201, body: "created")

      client.get(url)[:body].should == "ok"
      client.post(url, body: { test: "value" }, headers: { "X-Test" => "yes" })[:status].should == 201
    end
  end

  it "should follow GET and POST redirects between HTTPS and local HTTP" do
    remote = "https://example.com/start"
    local = "http://localhost:9292/next"
    final = "https://example.com/final"
    %i[get post].each do |method|
      stub_request(method, remote).to_return(status: 307, headers: { "Location" => local })
      stub_request(method, local).to_return(status: 307, headers: { "Location" => final })
      stub_request(method, final).to_return(status: 200, body: "ok")
      client.public_send(method, remote)[:body].should == "ok"
    end
  end

  it "should still reject unsupported schemes, missing hosts and fragments" do
    %w[ftp://localhost/test file:///tmp/test https:///test http://localhost/test#fragment].each do |url|
      expect { client.get(url) }.to raise_error(AuthProto::HTTPClient::SSRFError)
    end
  end

  it "should keep HTTPS certificate verification enabled and honor timeouts" do
    http = Net::HTTP.new("example.com")
    configured = AuthProto::InsecureHTTPClient.new(timeout: 3)
    configured.send(:configure_http_client!, http)
    http.use_ssl?.should be true
    http.verify_mode.should == OpenSSL::SSL::VERIFY_PEER
    http.open_timeout.should == 3
    http.read_timeout.should == 3
  end

  it "should retain response size limits" do
    url = "http://localhost:9292/test"
    stub_request(:get, url).to_return(status: 200, headers: {
                                        "Content-Length" => (AuthProto::HTTPClient::MAX_RESPONSE_SIZE + 1).to_s
                                      })
    expect { client.get(url) }.to raise_error(AuthProto::HTTPClient::HTTPError)
  end
end
