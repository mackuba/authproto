# frozen_string_literal: true

require 'json'
require 'jwt'

describe AuthProto::Token::Refresh do
  let(:successful_response) do
    { access_token: "new_token", token_type: "DPoP", expires_in: 3600,
      refresh_token: "rotated_refresh_token", scope: "atproto", sub: "subject_id" }
  end

  before do
    @previous_configuration = AuthProto.configuration
    AuthProto.reset_configuration
    AuthProto.configure do |configuration|
      configuration.http_client = AuthProto::HTTPClient.new
    end

    client_metadata = AuthProto::Metadata::ClientMetadata.new(
      "client_id" => "https://example.com/metadata.json",
      "grant_types" => %w[authorization_code refresh_token],
      "response_types" => ["code"],
      "redirect_uris" => ["https://example.com/callback"],
      "scope" => "atproto offline_access",
      "token_endpoint_auth_method" => "none",
      "dpop_bound_access_tokens" => true,
      "client_name" => "Example Client",
      "application_type" => "web"
    )

    # Set up a real session
    session = AuthProto::State::Session.new(
      client_id: "mock_client",
      scope: "atproto",
      auth_server: AuthProto::Metadata::AuthorizationServer.new(
        "issuer" => "https://example.com",
        "token_endpoint" => "https://example.com/token",
        "authorization_endpoint" => "https://example.com/auth",
        "response_types_supported" => ["code"],
        "grant_types_supported" => %w[authorization_code refresh_token],
        "code_challenge_methods_supported" => ["S256"],
        "token_endpoint_auth_methods_supported" => %w[private_key_jwt none],
        "token_endpoint_auth_signing_alg_values_supported" => %w[ES256],
        "scopes_supported" => %w[atproto],
        "dpop_signing_alg_values_supported" => %w[ES256],
        "pushed_authorization_request_endpoint" => "https://example.com/pushed_auth",
        "authorization_response_iss_parameter_supported" => true,
        "require_pushed_authorization_requests" => true,
        "client_id_metadata_document_supported" => true
      )
    )
    token_set = AuthProto::State::TokenSet.new(
      access_token: "existing_access_token",
      refresh_token: "mock_refresh_token",
      token_type: "DPoP",
      expires_in: 3600,
      scope: "atproto",
      sub: "subject_id"
    )
    session.tokens = token_set

    # Real DPoP client
    @dpop_client = AuthProto::DPoP::Client.new

    # Stub HTTP request
    stub_request(:post, "https://example.com/token").to_return(
      status: 200,
      body: successful_response.to_json,
      headers: { "Content-Type" => "application/json" }
    )

    # Token refresher
    @refresher = AuthProto::Token::Refresh.new(
      client_metadata: client_metadata,
      session: session,
      dpop_client: @dpop_client,
      auth_server: session.auth_server
    )
    @refresher.stubs(:sleep)
  end

  after do
    AuthProto.configuration = @previous_configuration
  end

  it "should refresh the token and return a new TokenSet" do
    token_set = @refresher.perform

    token_set.should be_an_instance_of(AuthProto::State::TokenSet)
    token_set.access_token.should == "new_token"
    token_set.scope.should == "atproto"
    token_set.refresh_token.should == "rotated_refresh_token"
  end

  it "should raise a Token::RefreshError after max retries are reached" do
    # Stub HTTP request to always fail
    stub_request(:post, "https://example.com/token").to_return(
      status: 500, # Internal Server Error
      body: { error: "server_error", error_description: "Something went wrong" }.to_json,
      headers: { "Content-Type" => "application/json" }
    )

    expect {
      @refresher.perform
    }.to raise_error(AuthProto::Token::RefreshError) { |error|
      error.message.should match("Token refresh failed after 3 attempts")
    }
    assert_requested :post, "https://example.com/token", times: 3
  end

  it "should retry a transport failure and return replacement tokens" do
    http_client = AuthProto.configuration.http_client
    http_client.expects(:post).twice
               .raises(AuthProto::HTTPClient::HTTPError.new("Connection lost", nil)).then
               .returns(status: 200, body: successful_response.to_json, headers: {})
    @refresher.perform.access_token.should == "new_token"
  end

  it "should let programming errors propagate without retrying" do
    AuthProto.configuration.http_client.expects(:post).once.raises(ArgumentError, "bad implementation")
    @refresher.expects(:sleep).never
    expect { @refresher.perform }.to raise_error(ArgumentError, "bad implementation")
  end

  it "should sign the nonce retry with the same key and the server's nonce" do
    proofs = []
    stub_request(:post, "https://example.com/token").with do |request|
      proofs << JWT.decode(request.headers["Dpop"], nil, false)
      URI.decode_www_form(request.body).to_h["refresh_token"] == "mock_refresh_token"
    end.to_return(
      { status: 400, body: { error: "use_dpop_nonce" }.to_json, headers: { "DPoP-Nonce" => "new-nonce" } },
      { status: 200, body: successful_response.to_json }
    )

    @refresher.perform.access_token.should == "new_token"
    proofs.length.should == 2
    proofs.first.first.should_not have_key("nonce")
    proofs.last.first["nonce"].should == "new-nonce"
    proofs.last.last["jwk"].should == proofs.first.last["jwk"]
    proofs.last.first["jti"].should_not == proofs.first.first["jti"]
  end

  it "should handle a further nonce challenge without losing its error metadata" do
    stub_request(:post, "https://example.com/token").to_return(
      { status: 400, body: { error: "use_dpop_nonce" }.to_json, headers: { "DPoP-Nonce" => "nonce-1" } },
      { status: 400, body: { error: "use_dpop_nonce" }.to_json, headers: { "DPoP-Nonce" => "nonce-2" } },
      { status: 200, body: successful_response.to_json }
    )
    @refresher.perform.access_token.should == "new_token"
    assert_requested :post, "https://example.com/token", times: 3
  end

  [nil, ""].each do |nonce|
    it "should reject a nonce challenge with missing or empty nonce #{nonce.inspect} without retrying" do
      stub_request(:post, "https://example.com/token").to_return(
        status: 400, body: { error: "use_dpop_nonce" }.to_json,
        headers: nonce.nil? ? {} : { "DPoP-Nonce" => nonce }
      )
      expect { @refresher.perform }.to raise_error(AuthProto::Token::RefreshError, /No DPoP nonce/) { |error|
        error.retry_possible.should be false
      }
      assert_requested :post, "https://example.com/token", times: 1
    end
  end

  { "invalid_grant" => /Refresh token has been invalidated/, "invalid_client" => /Refresh request failed/ }.each do |code, message|
    it "should report #{code} without retrying or masking the server error" do
      stub_request(:post, "https://example.com/token").to_return(
        status: 400, body: { error: code, error_description: "Server explanation" }.to_json
      )
      expect { @refresher.perform }.to raise_error(AuthProto::Token::RefreshError, message) { |error|
        error.message.should include("Server explanation")
        error.token_type.should == "refresh"
        error.error_code.should == "refresh_failed"
        error.retry_possible.should be false
      }
      assert_requested :post, "https://example.com/token", times: 1
    end
  end

  it "should report HTTP 401 without retrying" do
    stub_request(:post, "https://example.com/token").to_return(status: 401)
    expect { @refresher.perform }.to raise_error(AuthProto::Token::RefreshError, /Refresh token is invalid/)
    assert_requested :post, "https://example.com/token", times: 1
  end

  it "should retry a rate limited response" do
    stub_request(:post, "https://example.com/token").to_return(
      { status: 429, headers: { "Retry-After" => "1" } },
      { status: 200, body: successful_response.to_json }
    )
    @refresher.perform.access_token.should == "new_token"
    assert_requested :post, "https://example.com/token", times: 2
  end

  [200, 400].each do |status|
    ["invalid json", "[]", "null", '"string"'].each do |body|
      it "should report a malformed HTTP #{status} response #{body.inspect} without retrying" do
        stub_request(:post, "https://example.com/token").to_return(status: status, body: body)
        expect { @refresher.perform }.to raise_error(AuthProto::Token::RefreshError) { |error|
          error.retry_possible.should be false
          error.message.should_not include("after 3 attempts")
        }
        assert_requested :post, "https://example.com/token", times: 1
      end
    end
  end

  %i[access_token token_type expires_in scope sub].each do |field|
    it "should report a missing #{field} without retrying" do
      successful_response.delete(field)
      stub_request(:post, "https://example.com/token").to_return(status: 200, body: successful_response.to_json)
      expect { @refresher.perform }.to raise_error(AuthProto::Token::RefreshError, /Missing #{field}/)
      assert_requested :post, "https://example.com/token", times: 1
    end
  end

  { access_token: 123, token_type: "Bearer", expires_in: "3600", scope: [], sub: "someone_else", refresh_token: false }.each do |field, value|
    it "should reject invalid #{field} #{value.inspect} without retrying" do
      successful_response[field] = value
      stub_request(:post, "https://example.com/token").to_return(status: 200, body: successful_response.to_json)
      expect { @refresher.perform }.to raise_error(AuthProto::Token::RefreshError)
      assert_requested :post, "https://example.com/token", times: 1
    end
  end

  it "should reject a response that drops the session scope" do
    successful_response[:scope] = "other"
    stub_request(:post, "https://example.com/token").to_return(status: 200, body: successful_response.to_json)
    expect { @refresher.perform }.to raise_error(AuthProto::Token::RefreshError, /Invalid scope/)
    assert_requested :post, "https://example.com/token", times: 1
  end

  it "should refresh a restored expired session after a nonce challenge" do
    session = @refresher.session
    session.tokens.instance_variable_set(:@expires_at, Time.now - 3600)
    serializer = AuthProto::Serialization::Session.new
    restored = serializer.deserialize(serializer.serialize(session))
    restored.tokens.should be_expired
    refresher = described_class.new(session: restored, dpop_client: @dpop_client,
                                    auth_server: restored.auth_server, client_metadata: @refresher.client_metadata)
    stub_request(:post, "https://example.com/token").to_return(
      { status: 400, body: { error: "use_dpop_nonce" }.to_json, headers: { "DPoP-Nonce" => "restored-nonce" } },
      { status: 200, body: successful_response.to_json }
    )
    tokens = refresher.perform
    tokens.refresh_token.should == "rotated_refresh_token"
    tokens.sub.should == restored.did
    tokens.should_not be_expired
  end

  [200, 400].each do |status|
    it "should report an absent HTTP #{status} response body without retrying" do
      AuthProto.configuration.http_client.expects(:post).once.returns(status: status, body: nil, headers: {})
      expect { @refresher.perform }.to raise_error(AuthProto::Token::RefreshError) { |error|
        error.retry_possible.should be false
      }
    end
  end
end
