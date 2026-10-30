# frozen_string_literal: true

require 'json'

describe AuthProto::Metadata::AuthorizationServer do
  let(:valid_metadata) do
    {
      "issuer" => "https://auth.example.com",
      "authorization_endpoint" => "https://auth.example.com/authorize",
      "token_endpoint" => "https://auth.example.com/token",
      "response_types_supported" => ["code"],
      "grant_types_supported" => %w[authorization_code refresh_token],
      "code_challenge_methods_supported" => ["S256"],
      "token_endpoint_auth_methods_supported" => %w[private_key_jwt none],
      "token_endpoint_auth_signing_alg_values_supported" => ["ES256"],
      "scopes_supported" => %w[atproto email profile],
      "dpop_signing_alg_values_supported" => ["ES256"],
      "pushed_authorization_request_endpoint" => "https://auth.example.com/par",
      "authorization_response_iss_parameter_supported" => true,
      "require_pushed_authorization_requests" => true,
      "client_id_metadata_document_supported" => true
    }
  end

  let(:invalid_metadata_missing_field) { valid_metadata.except("issuer") }
  let(:invalid_metadata_bad_url) { valid_metadata.merge("issuer" => "http://auth.example.com") }
  let(:issuer_url) { "https://auth.example.com" }
  let(:mock_response) do
    { status: 200, headers: { 'content-type' => 'application/json' }, body: valid_metadata.to_json }
  end

  describe "#initialize" do
    it "should initialize successfully with valid metadata" do
      server = AuthProto::Metadata::AuthorizationServer.new(valid_metadata)
      server.issuer.should == valid_metadata["issuer"]
      server.authorization_endpoint.should == valid_metadata["authorization_endpoint"]
    end

    it "should raise an error if a required field is missing" do
      expect {
        AuthProto::Metadata::AuthorizationServer.new(invalid_metadata_missing_field)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should raise an error for an invalid HTTPS URL" do
      expect {
        AuthProto::Metadata::AuthorizationServer.new(invalid_metadata_bad_url)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end
  end

  describe ".from_issuer" do
    before do
      AuthProto.configuration.stubs(:http_client).returns(mock_http_client = mock)
      mock_http_client.stubs(:get).with(URI.join(issuer_url, '/.well-known/oauth-authorization-server').to_s,
                                      follow_redirects: false).returns(mock_response)
    end

    it "should fetch and parse metadata successfully" do
      server = AuthProto::Metadata::AuthorizationServer.from_issuer(issuer_url)
      server.issuer.should == valid_metadata["issuer"]
    end

    it "should raise an error if fetching metadata fails" do
      AuthProto.configuration.http_client.stubs(:get).raises(AuthProto::HTTPClient::HTTPError.new("Network error",
                                                                                                      {}))
      expect {
        AuthProto::Metadata::AuthorizationServer.from_issuer(issuer_url)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should raise an error if the metadata JSON is invalid" do
      mock_response[:body] = 'not-json'
      expect {
        AuthProto::Metadata::AuthorizationServer.from_issuer(issuer_url)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should raise an error if the issuer in metadata does not match the request issuer" do
      invalid_metadata = valid_metadata.merge("issuer" => "https://other.example.com")
      mock_response[:body] = invalid_metadata.to_json

      expect {
        AuthProto::Metadata::AuthorizationServer.from_issuer(issuer_url)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    ['http://auth.example.com', 'https://auth.example.com:443', 'https://auth.example.com:0443',
     'https://auth.example.com:', 'https://auth.example.com/path', 'https://user@auth.example.com',
     'https://@auth.example.com', 'https://auth.example.com?', 'https://auth.example.com#',
     'https:///path', '/relative', 'https://bad host'].each do |url|
      it "should reject invalid issuer URL #{url.inspect} before fetching metadata" do
        AuthProto.configuration.http_client.expects(:get).never
        expect { described_class.from_issuer(url) }
          .to raise_error(AuthProto::InvalidAuthorizationServer, /issuer URL/)
      end
    end

    ['https://auth.example.com/', 'https://auth.example.com:8443'].each do |url|
      context "with issuer #{url}" do
        let(:issuer_url) { url }

        it "should accept a root path or nondefault port with matching metadata" do
          mock_response[:body] = valid_metadata.merge('issuer' => issuer_url).to_json
          described_class.from_issuer(issuer_url).issuer.should == issuer_url
        end
      end
    end

    [201, 204, 301, 302, 303, 307, 308, 400, 404, 500].each do |status|
      it "should reject HTTP #{status} even with valid metadata" do
        mock_response[:status] = status
        expect { described_class.from_issuer(issuer_url) }
          .to raise_error(AuthProto::InvalidAuthorizationServer, /HTTP 200/)
      end
    end

    [nil, 'text/plain', 'text/html', 'application/jwk-set+json', 'application/jsonp'].each do |content_type|
      it "should reject content type #{content_type.inspect}" do
        mock_response[:headers]['content-type'] = content_type
        expect { described_class.from_issuer(issuer_url) }
          .to raise_error(AuthProto::InvalidAuthorizationServer, /application\/json/)
      end
    end

    it "should accept a JSON media type with parameters and case differences" do
      mock_response[:headers]['content-type'] = 'Application/JSON; charset=utf-8'
      described_class.from_issuer(issuer_url).issuer.should == issuer_url
    end

    [[], 'metadata', 42, true, nil].each do |metadata|
      it "should reject a JSON value that is not an object: #{metadata.inspect}" do
        mock_response[:body] = metadata.to_json
        expect { described_class.from_issuer(issuer_url) }
          .to raise_error(AuthProto::InvalidAuthorizationServer, /JSON object/)
      end
    end

    it "should reject an absent response body" do
      mock_response[:body] = nil
      expect { described_class.from_issuer(issuer_url) }
        .to raise_error(AuthProto::InvalidAuthorizationServer, /Invalid JSON/)
    end

    it "should require an exact issuer match" do
      mock_response[:body] = valid_metadata.merge('issuer' => "#{issuer_url}/").to_json
      expect { described_class.from_issuer(issuer_url) }
        .to raise_error(AuthProto::InvalidAuthorizationServer, /issuer mismatch/)
    end

    it "should not request a redirect destination" do
      AuthProto.configuration.stubs(:http_client).returns(AuthProto::HTTPClient.new)
      Resolv::DNS.any_instance.stubs(:getaddresses).returns([Resolv::IPv4.create('93.184.216.34')])
      stub_request(:get, "#{issuer_url}/.well-known/oauth-authorization-server")
        .to_return(status: 302, headers: { 'Location' => 'https://other.example.com/metadata' })
      destination = stub_request(:get, 'https://other.example.com/metadata')
        .to_return(status: 200, headers: { 'Content-Type' => 'application/json' }, body: valid_metadata.to_json)

      expect { described_class.from_issuer(issuer_url) }
        .to raise_error(AuthProto::InvalidAuthorizationServer, /HTTP 200/)
      destination.should_not have_been_requested
    end
  end

  describe "validation methods" do
    %w[
      response_types_supported
      grant_types_supported
      code_challenge_methods_supported
      token_endpoint_auth_methods_supported
      token_endpoint_auth_signing_alg_values_supported
      dpop_signing_alg_values_supported
      scopes_supported
    ].each do |field|
      it "should require #{field} to be an array" do
        [valid_metadata[field].join(' '), valid_metadata[field].to_h { |value| [value, true] }, 42, true].each do |value|
          expect { described_class.new(valid_metadata.merge(field => value)) }
            .to raise_error(AuthProto::InvalidAuthorizationServer, "#{field} must be an array")
        end
      end

      it "should require #{field} to contain only strings" do
        [nil, true, 42, {}, []].each do |value|
          invalid_data = valid_metadata.merge(field => valid_metadata[field] + [value])
          expect { described_class.new(invalid_data) }
            .to raise_error(AuthProto::InvalidAuthorizationServer, "#{field} must contain only strings")
        end
      end
    end

    it "should accept omitted or true require_request_uri_registration" do
      described_class.new(valid_metadata).issuer.should == issuer_url
      described_class.new(valid_metadata.merge('require_request_uri_registration' => true)).issuer.should == issuer_url
    end

    [false, nil, 'true', 'false', 1, [], {}].each do |value|
      it "should reject require_request_uri_registration set to #{value.inspect}" do
        expect { described_class.new(valid_metadata.merge('require_request_uri_registration' => value)) }
          .to raise_error(AuthProto::InvalidAuthorizationServer, 'require_request_uri_registration must be true')
      end
    end

    ['authorization_endpoint', 'token_endpoint', 'pushed_authorization_request_endpoint'].each do |field|
      ['#fragment', '#'].each do |fragment|
        it "should reject #{field} with #{fragment.inspect}" do
          invalid_data = valid_metadata.merge(field => valid_metadata[field] + fragment)
          expect { described_class.new(invalid_data) }
            .to raise_error(AuthProto::InvalidAuthorizationServer, /must not contain a fragment/)
        end
      end

      it "should allow #{field} to have a path and query" do
        url = 'https://auth.example.com/oauth/endpoint?tenant=example'
        described_class.new(valid_metadata.merge(field => url)).public_send(field).should == url
      end
    end

    it "should validate required fields" do
      server = AuthProto::Metadata::AuthorizationServer.new(valid_metadata)
      expect {
        server.send(:validate_boolean_field, valid_metadata, "nonexistent_field", true)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should validate response types" do
      invalid_response_types = valid_metadata.merge("response_types_supported" => [])
      expect {
        AuthProto::Metadata::AuthorizationServer.new(invalid_response_types)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should validate grant types" do
      invalid_grant_types = valid_metadata.merge("grant_types_supported" => ["authorization_code"])
      expect {
        AuthProto::Metadata::AuthorizationServer.new(invalid_grant_types)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should validate token endpoint auth methods" do
      invalid_auth_methods = valid_metadata.merge("token_endpoint_auth_methods_supported" => ["none"])
      expect {
        AuthProto::Metadata::AuthorizationServer.new(invalid_auth_methods)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end
  end
end
