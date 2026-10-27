# frozen_string_literal: true

require 'json'

describe AuthProto::ServerMetadata::AuthorizationServer do
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
  let(:mock_response) { { body: valid_metadata.to_json } }

  describe "#initialize" do
    it "should initialize successfully with valid metadata" do
      server = AuthProto::ServerMetadata::AuthorizationServer.new(valid_metadata)
      server.issuer.should == valid_metadata["issuer"]
      server.authorization_endpoint.should == valid_metadata["authorization_endpoint"]
    end

    it "should raise an error if a required field is missing" do
      expect {
        AuthProto::ServerMetadata::AuthorizationServer.new(invalid_metadata_missing_field)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should raise an error for an invalid HTTPS URL" do
      expect {
        AuthProto::ServerMetadata::AuthorizationServer.new(invalid_metadata_bad_url)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end
  end

  describe ".from_issuer" do
    before do
      AuthProto.configuration.stubs(:http_client).returns(mock_http_client = mock)
      mock_http_client.stubs(:get).with("#{issuer_url}/.well-known/oauth-authorization-server").returns(mock_response)
    end

    it "should fetch and parse metadata successfully" do
      server = AuthProto::ServerMetadata::AuthorizationServer.from_issuer(issuer_url)
      server.issuer.should == valid_metadata["issuer"]
    end

    it "should raise an error if fetching metadata fails" do
      AuthProto.configuration.http_client.stubs(:get).raises(AuthProto::HTTPClient::HTTPError.new("Network error",
                                                                                                      {}))
      expect {
        AuthProto::ServerMetadata::AuthorizationServer.from_issuer(issuer_url)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should raise an error if the metadata JSON is invalid" do
      AuthProto.configuration.http_client.stubs(:get).returns(body: "not-json")
      expect {
        AuthProto::ServerMetadata::AuthorizationServer.from_issuer(issuer_url)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should raise an error if the issuer in metadata does not match the request issuer" do
      invalid_metadata = valid_metadata.merge("issuer" => "https://other.example.com")
      AuthProto.configuration.http_client.stubs(:get).returns(body: invalid_metadata.to_json)

      expect {
        AuthProto::ServerMetadata::AuthorizationServer.from_issuer(issuer_url)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end
  end

  describe "validation methods" do
    it "should validate required fields" do
      server = AuthProto::ServerMetadata::AuthorizationServer.new(valid_metadata)
      expect {
        server.send(:validate_boolean_field, valid_metadata, "nonexistent_field", true)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should validate response types" do
      invalid_response_types = valid_metadata.merge("response_types_supported" => [])
      expect {
        AuthProto::ServerMetadata::AuthorizationServer.new(invalid_response_types)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should validate grant types" do
      invalid_grant_types = valid_metadata.merge("grant_types_supported" => ["authorization_code"])
      expect {
        AuthProto::ServerMetadata::AuthorizationServer.new(invalid_grant_types)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end

    it "should validate token endpoint auth methods" do
      invalid_auth_methods = valid_metadata.merge("token_endpoint_auth_methods_supported" => ["none"])
      expect {
        AuthProto::ServerMetadata::AuthorizationServer.new(invalid_auth_methods)
      }.to raise_error(AuthProto::InvalidAuthorizationServer)
    end
  end
end
