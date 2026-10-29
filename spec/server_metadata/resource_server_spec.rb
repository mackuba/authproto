# frozen_string_literal: true

require 'json'

describe AuthProto::ServerMetadata::ResourceServer do
  let(:valid_metadata) { { "resource" => valid_url, "authorization_servers" => ["https://auth.example.com"] } }
  let(:invalid_metadata_missing_servers) { {} }
  let(:invalid_metadata_multiple_servers) { { "authorization_servers" => ["https://auth1.example.com", "https://auth2.example.com"] } }
  let(:invalid_metadata_bad_url) { { "authorization_servers" => ["http://auth.example.com"] } }
  let(:valid_url) { "https://example.com" }
  let(:mock_response) do
    { status: 200, headers: { "content-type" => "application/json" }, body: valid_metadata.to_json }
  end

  describe "#initialize" do
    it "should initialize successfully with valid metadata" do
      server = AuthProto::ServerMetadata::ResourceServer.new(valid_metadata)
      server.authorization_servers.should == valid_metadata["authorization_servers"]
    end

    it "should raise an error if authorization_servers is missing" do
      expect {
        AuthProto::ServerMetadata::ResourceServer.new(invalid_metadata_missing_servers)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should raise an error if there are multiple authorization_servers" do
      expect {
        AuthProto::ServerMetadata::ResourceServer.new(invalid_metadata_multiple_servers)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should raise an error for invalid authorization server URL format" do
      expect {
        AuthProto::ServerMetadata::ResourceServer.new(invalid_metadata_bad_url)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end
  end

  describe ".from_url" do
    before do
      AuthProto.configuration.stubs(:http_client).returns(mock_http_client = mock)
      mock_http_client.stubs(:get).with(URI.join(valid_url, "/.well-known/oauth-protected-resource").to_s,
                                      follow_redirects: false).returns(mock_response)
    end

    it "should fetch and parse metadata successfully" do
      server = AuthProto::ServerMetadata::ResourceServer.from_url(valid_url)
      server.authorization_servers.should == valid_metadata["authorization_servers"]
    end

    it "should raise an error if fetching metadata fails" do
      AuthProto.configuration.http_client.stubs(:get).raises(AuthProto::HTTPClient::HTTPError.new("Network error",
                                                                                                      {}))
      expect {
        AuthProto::ServerMetadata::ResourceServer.from_url(valid_url)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should raise an error if the metadata JSON is invalid" do
      mock_response[:body] = "not-json"
      expect {
        AuthProto::ServerMetadata::ResourceServer.from_url(valid_url)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "rejects an absent response body" do
      mock_response[:body] = nil
      expect { described_class.from_url(valid_url) }
        .to raise_error(AuthProto::InvalidAuthorizationServer, /Invalid JSON/)
    end

    [201, 204, 301, 302, 303, 307, 308, 400, 404, 500].each do |status|
      it "rejects HTTP #{status} even with otherwise valid metadata" do
        mock_response[:status] = status
        expect { described_class.from_url(valid_url) }
          .to raise_error(AuthProto::InvalidAuthorizationServer, /HTTP 200/)
      end
    end

    [nil, "text/plain", "text/html", "application/jwk-set+json", "application/jsonp"].each do |content_type|
      it "rejects content type #{content_type.inspect}" do
        mock_response[:headers]["content-type"] = content_type
        expect { described_class.from_url(valid_url) }
          .to raise_error(AuthProto::InvalidAuthorizationServer, /application\/json/)
      end
    end

    it "accepts a JSON media type with parameters and case differences" do
      mock_response[:headers]["content-type"] = "Application/JSON; charset=utf-8"
      described_class.from_url(valid_url).authorization_servers.should == valid_metadata["authorization_servers"]
    end

    [[], "metadata", 42, true, nil].each do |metadata|
      it "rejects a JSON value that is not an object: #{metadata.inspect}" do
        mock_response[:body] = metadata.to_json
        expect { described_class.from_url(valid_url) }
          .to raise_error(AuthProto::InvalidAuthorizationServer, /JSON object/)
      end
    end

    [nil, 42, [], "https://other.example.com", "https://example.com/", "https://EXAMPLE.com",
     "https://example.com:443"].each do |resource|
      it "rejects a missing or nonmatching resource: #{resource.inspect}" do
        metadata = valid_metadata.merge("resource" => resource)
        metadata.delete("resource") if resource.nil?
        mock_response[:body] = metadata.to_json
        expect { described_class.from_url(valid_url) }
          .to raise_error(AuthProto::InvalidAuthorizationServer, /resource must match/)
      end
    end

    ["https://example.com#fragment", "https:///path", "/relative", "https://bad host",
     "https://user@example.com", "https://user:password@example.com", "https://@example.com",
     "https://example.com/pds", "https://example.com/pds/", "https://example.com//",
     "https://example.com?key=value", "https://example.com?", "https://example.com#"].each do |url|
      context "when the requested URL is #{url}" do
        it "rejects an invalid resource URL before fetching metadata" do
          AuthProto.configuration.http_client.expects(:get).never
          expect { described_class.from_url(url) }
            .to raise_error(AuthProto::InvalidAuthorizationServer, /[Rr]esource server URL/)
        end
      end
    end

    ["https://example.com/", "https://example.com:8443", "https://[2001:db8::1]:8443"].each do |url|
      context "when the requested URL is #{url}" do
        let(:valid_url) { url }

        it "accepts a root URL with an optional port and preserves exact resource matching" do
          described_class.from_url(valid_url).authorization_servers.should == valid_metadata["authorization_servers"]
        end
      end
    end

    context "when the resource uses HTTP" do
      let(:valid_url) { "http://localhost:9292" }

      it "allows HTTP metadata when InsecureHTTPClient is configured" do
        AuthProto.configuration.stubs(:http_client).returns(AuthProto::InsecureHTTPClient.new)
        stub_request(:get, "#{valid_url}/.well-known/oauth-protected-resource")
          .to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: valid_metadata.to_json)

        described_class.from_url(valid_url).authorization_servers.should == valid_metadata["authorization_servers"]
      end

      it "lets the standard HTTPClient reject HTTP before making a request" do
        AuthProto.configuration.stubs(:http_client).returns(AuthProto::HTTPClient.new)
        request = stub_request(:get, "#{valid_url}/.well-known/oauth-protected-resource")

        expect { described_class.from_url(valid_url) }
          .to raise_error(AuthProto::HTTPClient::SSRFError, /URL scheme/)
        expect(request).not_to have_been_requested
      end
    end

    it "compares the resource after JSON unescaping" do
      mock_response[:body] = valid_metadata.to_json.gsub("https://example.com", 'https:\/\/example.com')
      described_class.from_url(valid_url).authorization_servers.should == valid_metadata["authorization_servers"]
    end

    it "does not request a redirect destination" do
      AuthProto.configuration.stubs(:http_client).returns(AuthProto::HTTPClient.new)
      Resolv::DNS.any_instance.stubs(:getaddresses).returns([Resolv::IPv4.create("93.184.216.34")])
      stub_request(:get, "#{valid_url}/.well-known/oauth-protected-resource")
        .to_return(status: 302, headers: { "Location" => "https://other.example.com/metadata" })
      destination = stub_request(:get, "https://other.example.com/metadata")
        .to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: valid_metadata.to_json)

      expect { described_class.from_url(valid_url) }
        .to raise_error(AuthProto::InvalidAuthorizationServer, /HTTP 200/)
      expect(destination).not_to have_been_requested
    end
  end
end
