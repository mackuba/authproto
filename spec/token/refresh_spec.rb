# frozen_string_literal: true

require 'json'
require 'jwt'

describe AuthProto::Token::Refresh do
  let(:requested_scope) { 'atproto' }

  let(:successful_response) do
    { access_token: "new_token", token_type: "DPoP", expires_in: 3600,
      refresh_token: "rotated_refresh_token", scope: "atproto", sub: "did:plc:ewvi7nxzyoun6zhxrhs64oiz" }
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
      scope: requested_scope,
      pds: 'https://pds.example.com',
      auth_server: AuthProto::Metadata::AuthorizationServer.new(
        "issuer" => "https://example.com",
        "token_endpoint" => "https://example.com/token",
        'revocation_endpoint' => 'https://example.com/revoke',
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
      sub: "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
    )
    session.tokens = token_set

    Resolv::DNS.any_instance.stubs(:getaddresses).returns([Resolv::IPv4.create('93.184.216.34')])
    stub_request(:post, 'https://example.com/revoke').to_return(
      status: 200, headers: { 'DPoP-Nonce' => 'revoke-nonce' }
    )
    stub_request(:get, 'https://plc.directory/did:plc:ewvi7nxzyoun6zhxrhs64oiz').to_return(
      status: 200, headers: { 'Content-Type' => 'application/did+ld+json' }, body: {
        id: 'did:plc:ewvi7nxzyoun6zhxrhs64oiz',
        service: [{ id: '#atproto_pds', type: 'AtprotoPersonalDataServer',
                    serviceEndpoint: 'https://pds.example.com' }]
      }.to_json
    )

    # Real DPoP client
    @dpop_client = AuthProto::DPoP::Client.new

    # Stub HTTP request
    stub_request(:post, "https://example.com/token").to_return(
      status: 200,
      body: successful_response.to_json,
      headers: { "DPoP-Nonce" => "fixture-nonce", "Content-Type" => "application/json" }
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
    token_set = @refresher.perform_refresh

    token_set.should be_an_instance_of(AuthProto::State::TokenSet)
    token_set.access_token.should == "new_token"
    token_set.scope.should == "atproto"
    token_set.refresh_token.should == "rotated_refresh_token"
  end

  it "should retain and reuse the existing refresh token when no replacement is issued" do
    stub_request(:post, 'https://example.com/token').to_return(
      status: 200,
      headers: { 'Content-Type' => 'application/json', 'DPoP-Nonce' => 'nonce' },
      body: successful_response.except(:refresh_token).to_json
    )
    tokens = @refresher.perform_refresh

    tokens.access_token.should == 'new_token'
    tokens.refresh_token.should == 'mock_refresh_token'
    tokens.should be_renewable
    @refresher.session.tokens = tokens
    @refresher.perform_refresh.refresh_token.should == 'mock_refresh_token'

    assert_requested(:post, 'https://example.com/token', times: 2) do |request|
      URI.decode_www_form(request.body).to_h['refresh_token'] == 'mock_refresh_token'
    end
  end

  describe "with a partially approved grant" do
    let(:requested_scope) { 'atproto transition:email' }

    it "should omit scope when refreshing a partially granted authorization" do
      result = @refresher.perform_refresh

      result.scope.should == 'atproto'
      assert_requested(:post, 'https://example.com/token') do |request|
        form = URI.decode_www_form(request.body).to_h
        !form.key?('scope') && form['grant_type'] == 'refresh_token' && form['refresh_token'] == 'mock_refresh_token'
      end
    end
  end

  it "should accept an updated effective scope and retain it in the replacement tokens" do
    successful_response[:scope] = 'atproto repo:app.bsky.feed.post'
    stub_request(:post, 'https://example.com/token').to_return(
      status: 200, headers: { 'Content-Type' => 'application/json', 'DPoP-Nonce' => 'nonce' },
      body: successful_response.to_json
    )

    @refresher.perform_refresh.scope.should == successful_response[:scope]
  end

  it "should revoke the stored refresh token and skip refresh when the DID has moved to another PDS" do
    document = stub(pds_endpoint: 'https://other.example.com')
    DIDKit::DID.stubs(:new).with(@refresher.session.did).returns(stub(document: document))

    expect { @refresher.perform_refresh }.to raise_error(AuthProto::Token::RefreshError, /PDS does not match/) { |error|
      error.retry_possible.should be false
    }

    assert_not_requested :post, 'https://example.com/token'
    assert_requested :post, 'https://example.com/revoke', body: {
      token: 'mock_refresh_token', token_type_hint: 'refresh_token',
      client_id: @refresher.client_metadata.client_id
    }
  end

  it "should check the DID's PDS again before each refresh" do
    document = mock
    document.expects(:pds_endpoint).twice.returns('https://pds.example.com', 'https://other.example.com')
    DIDKit::DID.expects(:new).with(@refresher.session.did).twice.returns(stub(document: document))

    @refresher.perform_refresh.should be_a(AuthProto::State::TokenSet)
    expect { @refresher.perform_refresh }.to raise_error(AuthProto::Token::RefreshError, /PDS does not match/)

    assert_requested :post, 'https://example.com/token', times: 1
  end

  it "should retain the refresh token without revocation when identity lookup temporarily fails" do
    did = mock
    did.expects(:document).raises(DIDKit::APIError.new(Net::HTTPServiceUnavailable.new("1.1", "503", "Unavailable")))
    DIDKit::DID.stubs(:new).with(@refresher.session.did).returns(did)

    expect { @refresher.perform_refresh }.to raise_error(AuthProto::Token::RefreshError, /Could not resolve token subject/)

    assert_not_requested :post, 'https://example.com/token'
    assert_not_requested :post, 'https://example.com/revoke'
    @refresher.session.tokens.refresh_token.should == 'mock_refresh_token'
  end

  it "should preserve the refresh token when the DID document has no PDS endpoint" do
    document = stub(pds_endpoint: nil)
    DIDKit::DID.stubs(:new).with(@refresher.session.did).returns(stub(document: document))

    expect { @refresher.perform_refresh }.to raise_error(AuthProto::Token::RefreshError, /no PDS endpoint/)

    assert_not_requested :post, 'https://example.com/token'
    assert_not_requested :post, 'https://example.com/revoke'
    @refresher.session.tokens.refresh_token.should == 'mock_refresh_token'
  end

  it "should revoke the replacement refresh token when a refresh response changes the DID" do
    stub_request(:post, 'https://example.com/token').to_return(
      status: 200, headers: { 'Content-Type' => 'application/json', 'DPoP-Nonce' => 'nonce' },
      body: successful_response.merge(sub: 'did:plc:someone-else').to_json
    )

    expect { @refresher.perform_refresh }.to raise_error(AuthProto::Token::RefreshError, /Subject mismatch/)

    assert_requested :post, 'https://example.com/revoke', body: {
      token: 'rotated_refresh_token', token_type_hint: 'refresh_token',
      client_id: @refresher.client_metadata.client_id
    }
    @refresher.session.tokens.refresh_token.should == 'mock_refresh_token'
  end

  ['dpop', 'DPOP', 'dPoP'].each do |type|
    it "should accept refreshed token_type #{type} and return its canonical spelling" do
      stub_request(:post, 'https://example.com/token').to_return(
        status: 200, headers: { 'Content-Type' => 'application/json', 'DPoP-Nonce' => 'nonce' },
        body: successful_response.merge(token_type: type).to_json
      )

      @refresher.perform_refresh.token_type.should == 'DPoP'
    end
  end

  it "should raise a Token::RefreshError after max retries are reached" do
    # Stub HTTP request to always fail
    stub_request(:post, "https://example.com/token").to_return(
      status: 500, # Internal Server Error
      body: { error: "server_error", error_description: "Something went wrong" }.to_json,
      headers: { "DPoP-Nonce" => "fixture-nonce", "Content-Type" => "application/json" }
    )

    expect {
      @refresher.perform_refresh
    }.to raise_error(AuthProto::Token::RefreshError) { |error|
      error.message.should match("Token refresh failed after 3 attempts")
    }
    assert_requested :post, "https://example.com/token", times: 3
  end

  it "should retry a transport failure and return replacement tokens" do
    http_client = AuthProto.configuration.http_client
    http_client.expects(:post).twice
               .raises(AuthProto::HTTPClient::HTTPError.new("Connection lost", nil)).then
               .returns(status: 200, body: successful_response.to_json,
                        headers: { 'Content-Type' => 'application/json', 'DPoP-Nonce' => 'fixture-nonce' })
    @refresher.perform_refresh.access_token.should == "new_token"
  end

  it "should let programming errors propagate without retrying" do
    AuthProto.configuration.http_client.expects(:post).once.raises(ArgumentError, "bad implementation")
    @refresher.expects(:sleep).never
    expect { @refresher.perform_refresh }.to raise_error(ArgumentError, "bad implementation")
  end

  it "should sign the nonce retry with the same key and the server's nonce" do
    proofs = []
    stub_request(:post, "https://example.com/token").with do |request|
      proofs << JWT.decode(request.headers["Dpop"], nil, false)
      URI.decode_www_form(request.body).to_h["refresh_token"] == "mock_refresh_token"
    end.to_return(
      { status: 400, body: { error: "use_dpop_nonce" }.to_json, headers: { "DPoP-Nonce" => "new-nonce" } },
      { headers: { "Content-Type" => "application/json", "DPoP-Nonce" => "fixture-nonce" },
        status: 200, body: successful_response.to_json }
    )

    @refresher.perform_refresh.access_token.should == "new_token"
    proofs.length.should == 2
    proofs.first.first.should_not have_key("nonce")
    proofs.last.first["nonce"].should == "new-nonce"
    proofs.last.last["jwk"].should == proofs.first.last["jwk"]
    proofs.last.first["jti"].should_not == proofs.first.first["jti"]
  end

  [200, 400].each do |status|
    it "should reject a nonce-less second response with HTTP #{status}" do
      stub_request(:post, 'https://example.com/token').to_return(
        { status: 400, headers: { 'DPoP-Nonce' => 'challenge' }, body: '{"error":"use_dpop_nonce"}' },
        { status: status, body: status == 200 ? successful_response.to_json : '{"error":"use_dpop_nonce"}' }
      )

      expect {
        @refresher.perform_refresh
      }.to raise_error(AuthProto::DPoP::Client::Error, /Missing DPoP-Nonce/)
      assert_requested :post, 'https://example.com/token', times: 2
    end
  end

  it "should stop after a second nonce challenge and retain the latest nonce" do
    stub_request(:post, "https://example.com/token").to_return(
      { status: 400, body: { error: "use_dpop_nonce" }.to_json, headers: { "DPoP-Nonce" => "nonce-1" } },
      { status: 400, body: { error: "use_dpop_nonce" }.to_json, headers: { "DPoP-Nonce" => "nonce-2" } },
      { status: 200, body: successful_response.to_json }
    )
    expect { @refresher.perform_refresh }.to raise_error(AuthProto::Token::RefreshError, /use_dpop_nonce/)
    @dpop_client.nonce_manager.get(
      server_url: 'https://example.com', session_id: @refresher.session.session_id
    ).should == 'nonce-2'
    assert_requested :post, "https://example.com/token", times: 2
  end

  [nil, ""].each do |nonce|
    it "should reject a nonce challenge with missing or empty nonce #{nonce.inspect} without retrying" do
      stub_request(:post, "https://example.com/token").to_return(
        status: 400, body: { error: "use_dpop_nonce" }.to_json,
        headers: nonce.nil? ? {} : { "DPoP-Nonce" => nonce }
      )
      expect { @refresher.perform_refresh }.to raise_error(AuthProto::DPoP::Client::Error, /Missing DPoP-Nonce/)
      assert_requested :post, "https://example.com/token", times: 1
    end
  end

  { "invalid_grant" => /Refresh token has been invalidated/, "invalid_client" => /Refresh request failed/ }.each do |code, message|
    [400, 401].each do |status|
      it "should report #{code} on HTTP #{status} without retrying or masking the server error" do
        stub_request(:post, "https://example.com/token").to_return(
          headers: { "DPoP-Nonce" => "fixture-nonce" }, status: status, body: { error: code,
            error_description: "Server explanation" }.to_json
        )
        expect { @refresher.perform_refresh }.to raise_error(AuthProto::Token::RefreshError, message) { |error|
          error.message.should include(code)
          error.message.should include("Server explanation")
          error.token_type.should == "refresh"
          error.error_code.should == "refresh_failed"
          error.retry_possible.should be false
        }
        assert_requested :post, "https://example.com/token", times: 1
      end
    end
  end

  it "should report a missing or malformed HTTP 401 error body without blaming the refresh token" do
    stub_request(:post, "https://example.com/token").to_return(headers: { "DPoP-Nonce" => "fixture-nonce" },
      status: 401)
    expect { @refresher.perform_refresh }.to raise_error(AuthProto::Token::RefreshError, /error response/)
    assert_requested :post, "https://example.com/token", times: 1
  end

  [400, 401].each do |status|
    it "should preserve invalid_client without an error description on HTTP #{status}" do
      stub_request(:post, 'https://example.com/token').to_return(
        status: status, headers: { 'DPoP-Nonce' => 'nonce' }, body: '{"error":"invalid_client"}'
      )

      expect {
        @refresher.perform_refresh
      }.to raise_error(AuthProto::Token::RefreshError, /Refresh request failed: invalid_client/) { |error|
        error.retry_possible.should be false
        error.message.should_not include('Refresh token is invalid')
      }
      assert_requested :post, 'https://example.com/token', times: 1
    end
  end

  ['retry-after', 'Retry-After', 'rEtRy-AfTeR'].each do |header_name|
    it "should read the #{header_name} response header when rate limited" do
      AuthProto.configuration.http_client.expects(:post).times(3).returns(
        status: 429, headers: { 'DPoP-Nonce' => 'fixture-nonce', header_name => '37' }
      )

      expect {
        @refresher.perform_refresh
      }.to raise_error(AuthProto::Token::RefreshError, /Rate limited - retry after 37 seconds/)
    end
  end

  it "should retry a rate limited response" do
    stub_request(:post, "https://example.com/token").to_return(
      { status: 429, headers: { "DPoP-Nonce" => "fixture-nonce", "Retry-After" => "1" } },
      { headers: { "Content-Type" => "application/json", "DPoP-Nonce" => "fixture-nonce" },
        status: 200, body: successful_response.to_json }
    )
    @refresher.perform_refresh.access_token.should == "new_token"
    assert_requested :post, "https://example.com/token", times: 2
  end

  [200, 400, 401].each do |status|
    ["invalid json", "[]", "null", '"string"'].each do |body|
      it "should report a malformed HTTP #{status} response #{body.inspect} without retrying" do
        stub_request(:post, "https://example.com/token").to_return(
          headers: { "Content-Type" => "application/json", "DPoP-Nonce" => "fixture-nonce" },
          status: status, body: body)
        expect { @refresher.perform_refresh }.to raise_error(AuthProto::Token::RefreshError) { |error|
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
      stub_request(:post, "https://example.com/token").to_return(
        headers: { "Content-Type" => "application/json", "DPoP-Nonce" => "fixture-nonce" },
        status: 200, body: successful_response.to_json)
      expect { @refresher.perform_refresh }.to raise_error(AuthProto::Token::RefreshError, /Missing #{field}/)
      assert_requested :post, "https://example.com/token", times: 1
    end
  end

  { access_token: 123, token_type: "Bearer", expires_in: "3600", scope: [], sub: "someone_else", refresh_token: false }.each do |field, value|
    it "should reject invalid #{field} #{value.inspect} without retrying" do
      successful_response[field] = value
      stub_request(:post, "https://example.com/token").to_return(
        headers: { "Content-Type" => "application/json", "DPoP-Nonce" => "fixture-nonce" },
        status: 200, body: successful_response.to_json)
      expect { @refresher.perform_refresh }.to raise_error(AuthProto::Token::RefreshError)
      assert_requested :post, "https://example.com/token", times: 1
    end
  end

  it "should reject a response without the atproto scope" do
    successful_response[:scope] = "other"
    stub_request(:post, "https://example.com/token").to_return(
      headers: { "Content-Type" => "application/json", "DPoP-Nonce" => "fixture-nonce" },
      status: 200, body: successful_response.to_json)
    expect { @refresher.perform_refresh }.to raise_error(AuthProto::Token::RefreshError, /Invalid scope/)
    assert_requested :post, "https://example.com/token", times: 1
  end

  [{ headers: {} }, { headers: { 'Content-Type' => 'text/html' } }, { expires_in: 0 },
   { expires_in: -1 }, { refresh_token: '' }, { refresh_token: nil },
   { id_token: 'header.payload.signature' }, { id_token: nil }].each do |invalid_response|
    it "should reject malformed refresh responses #{invalid_response.inspect} without retrying or replacing tokens" do
      previous_tokens = @refresher.session.tokens
      data = successful_response.merge(invalid_response.except(:headers))
      response = {
        status: 200, headers: { 'Content-Type' => 'application/json' }, body: data.to_json
      }.merge(invalid_response.slice(:headers))
      response[:headers]['DPoP-Nonce'] = 'nonce'
      stub_request(:post, 'https://example.com/token').to_return(response)

      expect { @refresher.perform_refresh }.to raise_error(AuthProto::Token::RefreshError) { |error|
        error.retry_possible.should be false
      }

      @refresher.session.tokens.should equal(previous_tokens)
      assert_requested :post, 'https://example.com/token', times: 1
    end
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
      { headers: { "Content-Type" => "application/json", "DPoP-Nonce" => "fixture-nonce" },
        status: 200, body: successful_response.to_json }
    )
    tokens = refresher.perform_refresh
    tokens.refresh_token.should == "rotated_refresh_token"
    tokens.sub.should == restored.did
    tokens.should_not be_expired
  end

  [200, 400].each do |status|
    it "should report an absent HTTP #{status} response body without retrying" do
      AuthProto.configuration.http_client.expects(:post).once.returns(status: status, body: nil,
        headers: { "DPoP-Nonce" => "fixture-nonce"})
      expect { @refresher.perform_refresh }.to raise_error(AuthProto::Token::RefreshError) { |error|
        error.retry_possible.should be false
      }
    end

  it "should preserve a subject mismatch error when revocation fails" do
    stub_request(:post, 'https://example.com/token').to_return(
      status: 200, headers: { 'Content-Type' => 'application/json', 'DPoP-Nonce' => 'nonce' },
      body: successful_response.merge(sub: 'did:plc:someone-else').to_json
    )
    stub_request(:post, 'https://example.com/revoke').to_return(
      status: 503, headers: { 'DPoP-Nonce' => 'nonce' }
    )

    expect {
      @refresher.perform_refresh
    }.to raise_error(AuthProto::Token::RefreshError, /Subject mismatch/) { |error|
      error.retry_possible.should be false
    }

    assert_requested :post, 'https://example.com/revoke', times: 1
  end
  end
end
