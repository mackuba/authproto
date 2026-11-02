# frozen_string_literal: true

require 'json'
require 'net/http'
require 'resolv'
require 'uri'

require 'authproto/minisky'

describe Minisky::OAuthClient do
  let(:host) { "https://pds.example.com" }
  let(:endpoint) { "#{host}/xrpc/app.bsky.actor.getProfile" }
  let(:client_metadata) do
    {
      "client_id" => "https://client.example.com/metadata.json",
      "redirect_uris" => ["https://client.example.com/callback"],
      "grant_types" => %w[authorization_code refresh_token],
      "response_types" => ["code"],
      "scope" => "atproto",
      "token_endpoint_auth_method" => "none",
      "dpop_bound_access_tokens" => true,
      "application_type" => "web"
    }
  end
  let(:client) do
    Minisky::OAuthClient.new(
      host, client_id: client_metadata["client_id"], redirect_uri: client_metadata["redirect_uris"].first,
            metadata: client_metadata, signing_key: @signing_key
    )
  end
  let(:auth_server) do
    AuthProto::Metadata::AuthorizationServer.new(
      "issuer" => "https://auth.example.com",
      "token_endpoint" => "https://auth.example.com/token",
      "authorization_endpoint" => "https://auth.example.com/authorize",
      "response_types_supported" => ["code"],
      "grant_types_supported" => %w[authorization_code refresh_token],
      "code_challenge_methods_supported" => ["S256"],
      "token_endpoint_auth_methods_supported" => %w[private_key_jwt none],
      "token_endpoint_auth_signing_alg_values_supported" => ["ES256"],
      "scopes_supported" => ["atproto"],
      "dpop_signing_alg_values_supported" => ["ES256"],
      "pushed_authorization_request_endpoint" => "https://auth.example.com/par",
      "authorization_response_iss_parameter_supported" => true,
      "require_pushed_authorization_requests" => true,
      "client_id_metadata_document_supported" => true
    )
  end

  before do
    @previous_configuration = AuthProto.configuration
    AuthProto.reset_configuration
    AuthProto.configuration.http_client = AuthProto::HTTPClient.new
  end

  after do
    AuthProto.configuration = @previous_configuration
  end

  def token_set(expires_in: 3600)
    AuthProto::State::TokenSet.new(access_token: "access", refresh_token: "refresh", token_type: "DPoP",
                                     expires_in: expires_in, scope: "atproto", sub: "did:plc:alice")
  end

  def attach_session(expires_in: 3600)
    session = client.oauth_client.session_manager.create_session(
      client_id: client_metadata["client_id"], scope: "atproto", auth_server: auth_server
    )
    session.tokens = token_set(expires_in: expires_in)
    client.oauth_client.session_manager.update_session(session)
    client.instance_variable_set(:@session_id, session.session_id)
    session
  end

  def response_headers(nonce = "pds-nonce")
    { "Content-Type" => "application/json", "DPoP-Nonce" => nonce }
  end

  def stub_refresh
    # HTTPClient validates DNS before the mocked HTTP request.
    Resolv::DNS.any_instance.stubs(:getaddresses).returns([Resolv::IPv4.create("93.184.216.34")])
    stub_request(:post, "https://auth.example.com/token").with do |request|
      URI.decode_www_form(request.body).to_h["grant_type"] == "refresh_token"
    end.to_return(status: 200, headers: response_headers("auth-nonce"), body: {
      access_token: "new-access", refresh_token: "new-refresh", token_type: "DPoP",
      expires_in: 3600, scope: "atproto", sub: "did:plc:alice"
    }.to_json)
  end

  def stub_authorization_metadata
    Resolv::DNS.any_instance.stubs(:getaddresses).returns([Resolv::IPv4.create("93.184.216.34")])
    stub_request(:get, "#{host}/.well-known/oauth-protected-resource")
      .to_return(status: 200, headers: { "Content-Type" => "application/json" },
                 body: { resource: host, authorization_servers: [auth_server.issuer] }.to_json)
    stub_request(:get, "#{auth_server.issuer}/.well-known/oauth-authorization-server")
      .to_return(status: 200, headers: { 'Content-Type' => 'application/json' }, body: auth_server.to_h.to_json)
  end

  it "should authorize a localhost public client using PKCE and DPoP without a client assertion" do
    client_metadata["client_id"] = "http://localhost/"
    client_metadata["application_type"] = "native"
    client_metadata["redirect_uris"] = ["http://127.0.0.1:9292/callback"]
    client_metadata["token_endpoint_auth_method"] = "none"
    stub_authorization_metadata
    AuthProto::PAR::ClientAssertion.expects(:new).never
    stub_request(:post, "#{auth_server.issuer}/par").with do |request|
      form = URI.decode_www_form(request.body).to_h
      form["client_id"] == "http://localhost/" && form["code_challenge_method"] == "S256" &&
        !form.key?("client_assertion") && !form.key?("client_assertion_type") && request.headers.key?("Dpop")
    end.to_return(
      status: 201, headers: { "DPoP-Nonce" => "fixture-nonce", "Content-Type" => "application/json" },
      body: { request_uri: "urn:example:par", expires_in: 90 }.to_json
    )

    result = client.authorize(pds: host)
    URI(result[:url]).host.should == "auth.example.com"
    client.session_id.should == result[:session_id]
    client.oauth_client.session_manager.get_session(result[:session_id]).signing_key_id.should be_nil
  end

  it "should submit a native custom-scheme callback unchanged in PAR" do
    callback = "com.example.client:/oauth/callback"
    client_metadata.merge!("application_type" => "native", "token_endpoint_auth_method" => "none",
                           "redirect_uris" => [callback])
    stub_authorization_metadata
    stub_request(:post, "#{auth_server.issuer}/par").with do |request|
      URI.decode_www_form(request.body).to_h["redirect_uri"] == callback
    end.to_return(
      status: 201, headers: { "DPoP-Nonce" => "fixture-nonce", "Content-Type" => "application/json" },
      body: { request_uri: "urn:example:par", expires_in: 90 }.to_json
    )

    URI(client.authorize(pds: host)[:url]).host.should == "auth.example.com"
  end

  [false, true].each do |use_uri|
    it "should sign PAR retries, code exchange and refresh with the separate key when jwks_uri is #{use_uri}" do
      key = JOSE::JWK.generate_key([:ec, "P-256"])
      @signing_key = key.to_map.to_h.merge("kid" => "client-key", "key_ops" => ["sign"])
      client_metadata.merge!("token_endpoint_auth_method" => "private_key_jwt", "token_endpoint_auth_signing_alg" => "ES256")
      if use_uri
        client_metadata["jwks_uri"] = "https://client.example.com/keys.json"
      else
        client_metadata["jwks"] = { "keys" => [@signing_key.except("d").merge("key_ops" => ["verify"])] }
      end
      signer = AuthProto::PAR::ClientAssertion.new(client_id: client_metadata['client_id'], signing_key: @signing_key)
      AuthProto::PAR::ClientAssertion.expects(:new)
        .with(client_id: client_metadata['client_id'], signing_key: @signing_key).once.returns(signer)
      stub_authorization_metadata
      public_key = JWT::JWK.import(key.to_public_map.to_h).public_key
      assertions = []
      par_proofs = []
      validate_assertion = lambda do |request|
        form = URI.decode_www_form(request.body).to_h
        payload, header = JWT.decode(form.fetch("client_assertion"), public_key, true, algorithm: "ES256")
        assertions << payload["jti"]

        if form.key?('state')
          pending = client.oauth_client.session_manager.get_session_by_state_token(form['state'])
          pending.signing_key_id.should == header['kid']
        end

        payload["iss"] == client_metadata["client_id"] && payload["sub"] == client_metadata["client_id"] &&
          payload["aud"] == auth_server.issuer && header["kid"] == "client-key" &&
          form["client_assertion_type"] == AuthProto::PAR::CLIENT_ASSERTION_TYPE
      end
      stub_request(:post, "#{auth_server.issuer}/par").with(&validate_assertion)
        .to_return do |request|
          par_proofs << JWT.decode(request.headers.fetch('Dpop'), nil, false).first

          if par_proofs.length == 1
            { status: 400, headers: { 'DPoP-Nonce' => 'par-nonce' }, body: '{"error":"use_dpop_nonce"}' }
          else
            { status: 201, headers: { 'DPoP-Nonce' => 'par-success', 'Content-Type' => 'application/json' },
              body: { request_uri: 'urn:example:par', expires_in: 90 }.to_json }
          end
        end
      stub_request(:post, auth_server.token_endpoint).with(&validate_assertion).to_return(
        { status: 400, headers: { 'DPoP-Nonce' => 'token-challenge' }, body: '{"error":"use_dpop_nonce"}' },
        { status: 200, headers: { 'DPoP-Nonce' => 'token-success' }, body: {
          access_token: 'new-access', refresh_token: 'new-refresh', token_type: 'DPoP',
          expires_in: 3600, scope: 'atproto', sub: 'did:plc:alice'
        }.to_json }
      )

      auth = client.authorize(pds: host)
      session = client.oauth_client.session_manager.get_session(auth[:session_id])
      session.signing_key_id.should == 'client-key'
      state_token = session.state_token
      nonces = client.oauth_client.dpop_client.nonce_manager
      nonces.get(server_url: auth_server.issuer, session_id: session.session_id).should == 'par-success'
      client.handle_callback(code: 'code', state: state_token, iss: auth_server.issuer,
                             expected_session_id: auth[:session_id])
      nonces.get(server_url: auth_server.issuer, session_id: session.session_id).should == 'token-success'
      client.oauth_client.session_manager.get_session(session.session_id).state_token.should be_nil
      client.oauth_client.session_manager.get_session(session.session_id).signing_key_id.should == 'client-key'
      AuthProto.storage.exists?(AuthProto::Storage::KeyBuilder.state_key(state_token)).should be_falsey

      expect {
        client.handle_callback(code: 'code', state: state_token, iss: auth_server.issuer,
                               expected_session_id: auth[:session_id])
      }.to raise_error(AuthProto::Client::CallbackError, "Invalid state parameter")

      client.perform_token_refresh[:refresh_token].should == "new-refresh"
      client.oauth_client.session_manager.get_session(session.session_id).signing_key_id.should == 'client-key'
      AuthProto.storage.exists?(AuthProto::Storage::KeyBuilder.state_key(state_token)).should be_falsey
      assertions.length.should == 5
      assertions.uniq.length.should == 5
      par_proofs.length.should == 2
      par_proofs.map { |proof| proof['jti'] }.uniq.length.should == 2
      par_proofs.last['nonce'].should == 'par-nonce'
      assert_not_requested :get, "https://client.example.com/keys.json"
    end
  end

  it "should persist distinct session keys from PAR through callbacks and data proofs on a new client" do
    stub_authorization_metadata
    original_keys = {}
    stub_request(:post, "#{auth_server.issuer}/par").to_return do |request|
      state = URI.decode_www_form(request.body).to_h.fetch('state')
      pending = client.oauth_client.session_manager.get_session_by_state_token(state)
      original_keys[pending.session_id] = pending.dpop_key
      pending.dpop_key.key.verify(request.headers.fetch('Dpop')).first.should be_truthy
      { status: 201, headers: { "DPoP-Nonce" => "fixture-nonce", 'Content-Type' => 'application/json' },
        body: { request_uri: 'urn:example:par', expires_in: 90 }.to_json }
    end
    authorizations = Array.new(2) { client.authorize(pds: host) }
    original_keys.values.map(&:public_jwk).uniq.length.should == 2
    restored = described_class.new(
      host, client_id: client_metadata['client_id'], redirect_uri: client_metadata['redirect_uris'].first,
      metadata: client_metadata
    )
    stub_request(:post, auth_server.token_endpoint).to_return do |request|
      session_id = URI.decode_www_form(request.body).to_h.fetch('code')
      original_keys.fetch(session_id).key.verify(request.headers.fetch('Dpop')).first.should be_truthy
      { headers: { "DPoP-Nonce" => "fixture-nonce" }, status: 200, body: {
        access_token: "access-#{session_id}", refresh_token: 'refresh', token_type: 'DPoP',
        expires_in: 3600, scope: 'atproto', sub: 'did:plc:alice'
      }.to_json }
    end

    authorizations.reverse_each do |auth|
      pending = restored.oauth_client.session_manager.get_session(auth[:session_id])
      restored.handle_callback(
        code: pending.session_id, state: pending.state_token, iss: auth_server.issuer,
        expected_session_id: pending.session_id
      )
    end

    (authorizations + authorizations.reverse).each do |auth|
      session_id = auth[:session_id]
      headers = restored.oauth_client.auth_headers(session_id: session_id, method: 'GET', url: endpoint)
      original_keys.fetch(session_id).key.verify(headers.fetch('DPoP')).first.should be_truthy
      headers.fetch('Authorization').should == "DPoP access-#{session_id}"
    end
  end

  describe "restored signing key binding" do
    before do
      @signing_key = JOSE::JWK.generate_key([:ec, 'P-256']).to_map.to_h.merge('kid' => 'original-key')
      client_metadata.merge!(
        'token_endpoint_auth_method' => 'private_key_jwt', 'token_endpoint_auth_signing_alg' => 'ES256',
        'jwks_uri' => 'https://client.example.com/keys.json'
      )
    end

    let(:pending_session) do
      stub_authorization_metadata
      stub_request(:post, "#{auth_server.issuer}/par").to_return(
        status: 201, headers: { "DPoP-Nonce" => "fixture-nonce", 'Content-Type' => 'application/json' },
        body: { request_uri: 'urn:example:par', expires_in: 90 }.to_json
      )
      auth = client.authorize(pds: host)
      client.oauth_client.session_manager.get_session(auth[:session_id])
    end
    let(:replacement_key) do
      JOSE::JWK.generate_key([:ec, 'P-256']).to_map.to_h.merge('kid' => 'replacement-key')
    end

    def restore_client(signing_key)
      original = pending_session
      described_class.new(
        host, client_id: client_metadata['client_id'], redirect_uri: client_metadata['redirect_uris'].first,
        metadata: client_metadata, signing_key: signing_key, session_id: original.session_id
      )
    end

    it "should reject a different signing key before sending the restored session's authorization code" do
      restored = restore_client(replacement_key)
      restored.oauth_client.session_manager.get_session(pending_session.session_id).should be_nil

      expect {
        restored.handle_callback(
          code: 'code', state: pending_session.state_token, iss: auth_server.issuer,
          expected_session_id: pending_session.session_id
        )
      }.to raise_error(AuthProto::Client::CallbackError, "Invalid state parameter")

      assert_not_requested :post, auth_server.token_endpoint
      stored = client.oauth_client.session_manager.get_session_by_state_token(pending_session.state_token)
      stored.should be_pending
      stored.signing_key_id.should == 'original-key'
    end

    it "should reject a different signing key before sending the restored session's refresh token" do
      pending_session.tokens = token_set
      client.oauth_client.session_manager.complete_authorization(pending_session)
      restored = restore_client(replacement_key)
      restored.oauth_client.session_manager.get_session(pending_session.session_id).should be_nil

      expect {
        restored.perform_token_refresh
      }.to raise_error(AuthProto::Client::TokenError, "Invalid session")

      assert_not_requested :post, auth_server.token_endpoint
      stored = client.oauth_client.session_manager.get_session(pending_session.session_id)
      stored.signing_key_id.should == 'original-key'
      stored.tokens.refresh_token.should == 'refresh'
    end

    it "should refresh a restored session with its original signing key" do
      pending_session.tokens = token_set
      client.oauth_client.session_manager.complete_authorization(pending_session)
      restored = restore_client(@signing_key)
      stub_refresh

      restored.perform_token_refresh[:refresh_token].should == 'new-refresh'
      stored = restored.oauth_client.session_manager.get_session(pending_session.session_id)
      stored.signing_key_id.should == 'original-key'
    end

    it "should accept an older serialized session without a signing key ID" do
      state_token = pending_session.state_token
      session_key = AuthProto::Storage::KeyBuilder.session_key(pending_session.session_id)
      serialized = JSON.parse(AuthProto.storage.get(session_key))
      serialized.fetch('data').delete('signing_key_id')
      AuthProto.storage.set(session_key, JSON.generate(serialized))
      restored = restore_client(@signing_key)
      stub_request(:post, auth_server.token_endpoint).to_return(headers: { "DPoP-Nonce" => "fixture-nonce" },
        status: 200, body: {
        access_token: 'access', refresh_token: 'refresh', token_type: 'DPoP',
        expires_in: 3600, scope: 'atproto', sub: 'did:plc:alice'
      }.to_json)

      restored.handle_callback(
        code: 'code', state: state_token, iss: auth_server.issuer, expected_session_id: pending_session.session_id
      )[:access_token].should == 'access'
      restored.perform_token_refresh[:refresh_token].should == 'refresh'

      stored = restored.oauth_client.session_manager.get_session(pending_session.session_id)
      stored.signing_key_id.should be_nil
      assert_requested :post, auth_server.token_endpoint, times: 2
    end
  end

  it "should retain the state token and lookup when the token exchange fails" do
    session = client.oauth_client.session_manager.create_session(
      client_id: client_metadata['client_id'], scope: 'atproto', auth_server: auth_server
    )
    client.oauth_client.stubs(:exchange_code).raises(AuthProto::Client::TokenError, "Token exchange failed")

    expect {
      client.handle_callback(code: 'code', state: session.state_token, iss: auth_server.issuer,
                             expected_session_id: session.session_id)
    }.to raise_error(AuthProto::Client::TokenError, "Token exchange failed")

    restored = client.oauth_client.session_manager.get_session_by_state_token(session.state_token)
    restored.session_id.should == session.session_id
    restored.state_token.should == session.state_token
    restored.tokens.should be_nil
  end

  it "should authorize a resolved handle and persist its DID and discovered issuer" do
    did = "did:plc:abcdefghijklmnopqrstuvwx"
    client_metadata["token_endpoint_auth_method"] = "none"
    stub_authorization_metadata

    Resolv::DNS.any_instance.stubs(:getresources).returns([Resolv::DNS::Resource::IN::TXT.new("did=#{did}")])

    stub_request(:get, "#{DIDKit::DEFAULT_PLC_DIRECTORY}/#{did}")
      .to_return(status: 200, headers: { "Content-Type" => "application/did+json" }, body: {
        id: did,
        alsoKnownAs: ["at://alice.example.com"],
        service: [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: host }]
      }.to_json)

    stub_request(:post, "#{auth_server.issuer}/par")
      .with { |request| URI.decode_www_form(request.body).to_h["login_hint"] == "@Alice.Example.Com" }
      .to_return(
        status: 201, headers: { "DPoP-Nonce" => "fixture-nonce", "Content-Type" => "application/json" },
        body: { request_uri: "urn:example:par", expires_in: 90 }.to_json
      )

    result = client.authorize(handle: "@Alice.Example.Com")
    session = client.oauth_client.session_manager.get_session(result[:session_id])

    session.did.should == did
    session.auth_server.issuer.should == auth_server.issuer
    URI(result[:url]).host.should == "auth.example.com"
  end

  describe "identity discovery during authorization" do
    let(:did) { "did:plc:abcdefghijklmnopqrstuvwx" }
    let(:handle) { "alice.example.com" }

    def stub_identity_document(aliases: ["at://alice.example.com"], pds: host, document_did: did)
      Resolv::DNS.any_instance.stubs(:getresources).returns([Resolv::DNS::Resource::IN::TXT.new("did=#{did}")])

      services = pds ? [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: pds }] : []

      stub_request(:get, "#{DIDKit::DEFAULT_PLC_DIRECTORY}/#{did}")
        .to_return(status: 200, headers: { "Content-Type" => "application/did+json" }, body: {
          id: document_did, alsoKnownAs: aliases, service: services
        }.to_json)
    end

    it "should accept a DID without a claimed handle" do
      client_metadata["token_endpoint_auth_method"] = "none"
      stub_authorization_metadata
      stub_identity_document(aliases: [])

      Resolv::DNS.any_instance.expects(:getresources).never

      stub_request(:post, "#{auth_server.issuer}/par")
        .to_return(
          status: 201, headers: { "DPoP-Nonce" => "fixture-nonce", "Content-Type" => "application/json" },
          body: { request_uri: "urn:example:par", expires_in: 90 }.to_json
        )

      result = client.authorize(handle: did)
      client.oauth_client.session_manager.get_session(result[:session_id]).did.should == did
    end

    it "should reject an invalid handle before server discovery" do
      expect { client.authorize(handle: "invalid handle") }.to raise_error(AuthProto::Error, /resolve or verify/)

      WebMock.should_not have_requested(:get, /oauth-protected-resource/)
    end

    [[], ["at://other.example.com"], ["at://other.example.com", "at://alice.example.com"]].each do |aliases|
      it "should reject an unverified primary handle (#{aliases.inspect}) before server discovery" do
        stub_identity_document(aliases: aliases)

        expect { client.authorize(handle: handle) }.to raise_error(AuthProto::Error, /resolve or verify/)

        WebMock.should_not have_requested(:get, /oauth-protected-resource/)
      end
    end

    [nil, "http://pds.example.com"].each do |pds|
      it "should reject a missing or non-HTTPS PDS #{pds.inspect} before server discovery" do
        stub_identity_document(pds: pds)

        expect { client.authorize(handle: handle) }.to raise_error(AuthProto::Error, /No HTTPS PDS/)

        WebMock.should_not have_requested(:get, /oauth-protected-resource/)
      end
    end

    it "should propagate DIDKit document errors before server discovery" do
      stub_identity_document(document_did: "did:plc:zyxwvutsrqponmlkjihgfedc")

      expect { client.authorize(handle: handle) }.to raise_error(DIDKit::FormatError, /doesn't match expected DID/)

      WebMock.should_not have_requested(:get, /oauth-protected-resource/)
    end
  end

  it "should disable Minisky password token management" do
    client.auto_manage_tokens.should be false
    client.send_auth_headers.should be true
    client.config.should be_nil
  end

  it "should retain existing memory sessions when another client is created" do
    session = attach_session
    Minisky::OAuthClient.new(
      host, client_id: client_metadata["client_id"], redirect_uri: client_metadata["redirect_uris"].first,
            metadata: client_metadata
    )
    client.oauth_client.session_manager.get_session(session.session_id).should_not be_nil
  end

  it "should require an explicit expected session ID even when it remembers a pending session" do
    client.instance_variable_set(:@session_id, 'pending')
    client.oauth_client.expects(:handle_callback).never

    expect {
      client.handle_callback(code: 'code', state: 'state', iss: 'issuer')
    }.to raise_error(ArgumentError, /missing keyword: :expected_session_id/)
  end

  it "should delegate login and remember the callback session" do
    client.oauth_client.expects(:authorize).with(handle: "alice.example.com")
          .returns(url: "https://auth.example.com/authorize", session_id: "pending")
    client.authorize(handle: "alice.example.com")[:session_id].should == "pending"
    client.session_id.should == "pending"
    client.oauth_client.expects(:handle_callback).with(code: 'code', state: 'state', iss: 'issuer',
                                                     expected_session_id: 'pending')
          .returns(session_id: "authorized")
    client.handle_callback(code: 'code', state: 'state', iss: 'issuer', expected_session_id: 'pending')
    client.session_id.should == "authorized"
  end

  it "should omit query params from GET proofs, preserve request params and headers, and save response nonces" do
    attach_session
    stub_request(:get, endpoint).with(query: { actor: "alice.example.com" }, headers: {
                                        "Authorization" => "DPoP access", "X-Test" => "yes"
                                      }) do |request|
      payload = JWT.decode(request.headers["Dpop"], nil, false).first
      payload["htm"] == "GET" && payload["htu"] == endpoint && payload.key?("ath")
    end.to_return(status: 200, headers: response_headers, body: '{"did":"did:plc:alice"}')

    result = client.get_request("app.bsky.actor.getProfile", { actor: "alice.example.com" },
                                headers: { "X-Test" => "yes", "authorization" => "Bearer wrong" })
    result["did"].should == "did:plc:alice"
    client.oauth_client.dpop_client.nonce_manager.get(
      server_url: host, session_id: client.session_id
    ).should == "pds-nonce"
  end

  it "should allow unauthenticated requests without a session or nonce header" do
    stub_request(:get, endpoint).with { |request| !request.headers.key?("Authorization") }
                                .to_return(status: 200, headers: { "DPoP-Nonce" => "fixture-nonce",
                                  "Content-Type" => "application/json" }, body: "{}")
    client.get_request("app.bsky.actor.getProfile", auth: false).should == {}
  end

  it "should reject authenticated requests before login" do
    expect { client.get_request("app.bsky.actor.getProfile") }.to raise_error(Minisky::AuthError)
  end

  it "should return :ok from check_access when no refresh is needed" do
    attach_session
    client.oauth_client.expects(:refresh_token).never
    client.check_access.should == :ok
  end

  it "should return :refreshed from check_access after refreshing expired tokens" do
    attach_session(expires_in: -10)
    stub_refresh
    client.check_access.should == :refreshed
    client.oauth_client.get_tokens(client.session_id)[:access_token].should == "new-access"
  end

  it "should apply a PDS nonce challenge only to the session making the request" do
    session = attach_session
    other = client.oauth_client.session_manager.create_session(
      client_id: client_metadata['client_id'], scope: 'atproto'
    )
    nonces = client.oauth_client.dpop_client.nonce_manager
    nonces.update(nonce: 'other-session', server_url: host, session_id: other.session_id)
    proofs = []
    stub_request(:get, endpoint).to_return do |request|
      proofs << JWT.decode(request.headers.fetch('Dpop'), nil, false).first

      if proofs.length == 1
        { status: 401, headers: {
          'DPoP-Nonce' => 'request-session', 'WWW-Authenticate' => 'DPoP error="use_dpop_nonce"'
        } }
      else
        { status: 200, headers: response_headers('request-session'), body: '{"ok":true}' }
      end
    end

    client.get_request('app.bsky.actor.getProfile').should == { 'ok' => true }
    proofs.length.should == 2
    proofs.first.should_not have_key('nonce')
    proofs.last['nonce'].should == 'request-session'
    nonces.get(server_url: host, session_id: other.session_id).should == 'other-session'
    nonces.get(server_url: host, session_id: session.session_id).should == 'request-session'
  end

  it "should reuse the persisted DPoP key when refreshing a session from a new client" do
    session = attach_session(expires_in: -10)
    restored = described_class.new(host, client_id: client_metadata["client_id"],
                                  redirect_uri: client_metadata["redirect_uris"].first, metadata: client_metadata,
                                  session_id: session.session_id)
    original_public_key = session.dpop_key.public_jwk
    stub_refresh
    stub_request(:post, "https://auth.example.com/token").with do |request|
      JWT.decode(request.headers["Dpop"], nil, false).last["jwk"] == original_public_key
    end.to_return(headers: { "DPoP-Nonce" => "fixture-nonce" }, status: 200, body: {
      access_token: "restored-access", refresh_token: "restored-refresh", token_type: "DPoP",
      expires_in: 3600, scope: "atproto", sub: "did:plc:alice"
    }.to_json)

    restored.check_access.should == :refreshed
    restored.oauth_client.get_tokens(session.session_id)[:refresh_token].should == "restored-refresh"
    assert_requested :post, "https://auth.example.com/token", times: 1
  end

  it "should raise from check_access when OAuth login has not completed" do
    expect { client.check_access }.to raise_error(Minisky::AuthError)
  end

  it "should refresh an expired token and store the rotated tokens before sending the GET" do
    attach_session(expires_in: -10)
    stub_refresh
    stub_request(:get, endpoint).with(headers: { "Authorization" => "DPoP new-access" })
                                .to_return(status: 200, headers: response_headers, body: "{}")
    client.get_request("app.bsky.actor.getProfile")
    client.oauth_client.get_tokens(client.session_id)[:refresh_token].should == "new-refresh"
  end

  it "should retry a nonce challenge with a fresh proof and the new nonce" do
    attach_session
    proofs = []
    stub_request(:get, endpoint).to_return do |request|
      proofs << request.headers["Dpop"]
      payload = JWT.decode(proofs.last, nil, false).first
      if proofs.length == 1
        { status: 401, headers: response_headers("challenge").merge(
          "WWW-Authenticate" => 'Bearer realm="api", DPoP error="use_dpop_nonce"'
        ), body: "{}" }
      else
        payload["nonce"].should == "challenge"
        { status: 200, headers: response_headers("next-nonce"), body: "{}" }
      end
    end
    client.get_request("app.bsky.actor.getProfile")
    proofs.uniq.length.should == 2
  end

  it "should stop after two nonce retries and preserve Minisky's API error" do
    attach_session
    stub_request(:get, endpoint).to_return(status: 401, headers: response_headers.merge(
      "WWW-Authenticate" => 'DPoP error="use_dpop_nonce"'
    ), body: '{"error":"use_dpop_nonce"}')
    expect { client.get_request("app.bsky.actor.getProfile") }.to raise_error(Minisky::ClientErrorResponse)
    WebMock.should have_requested(:get, endpoint).times(3)
  end

  it "should refresh once after invalid_token and stop if the token is still rejected" do
    attach_session
    stub_refresh
    stub_request(:get, endpoint).to_return(status: 401, headers: response_headers.merge(
      "WWW-Authenticate" => 'DPoP error="invalid_token", Bearer realm="api"'
    ), body: '{"error":"invalid_token"}')
    expect { client.get_request("app.bsky.actor.getProfile") }.to raise_error(Minisky::ClientErrorResponse)
    WebMock.should have_requested(:get, endpoint).times(2)
    WebMock.should have_requested(:post, "https://auth.example.com/token").times(1)
  end

  it "should not refresh for permission errors" do
    attach_session
    client.oauth_client.expects(:refresh_token).never
    stub_request(:get, endpoint).to_return(status: 403, headers: response_headers,
                                           body: '{"error":"Forbidden"}')
    expect { client.get_request("app.bsky.actor.getProfile") }.to raise_error(Minisky::ClientErrorResponse) { |error|
      error.error_type.should == "Forbidden"
    }
  end

  it "should not retry a transport timeout" do
    attach_session
    stub_request(:get, endpoint).to_timeout
    expect { client.get_request("app.bsky.actor.getProfile") }.to raise_error(Net::OpenTimeout)
    WebMock.should have_requested(:get, endpoint).times(1)
  end

  it "should reject successful responses without a nonce even when one is cached" do
    attach_session
    client.oauth_client.dpop_client.nonce_manager.update(
      nonce: "cached", server_url: host, session_id: client.session_id
    )
    stub_request(:get, endpoint).to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: "{}")
    expect {
      client.get_request("app.bsky.actor.getProfile")
    }.to raise_error(AuthProto::DPoP::Client::Error, /Missing DPoP-Nonce/)
    client.oauth_client.dpop_client.nonce_manager.get(
      server_url: host, session_id: client.session_id
    ).should == "cached"
  end

  it "should reject nonce challenges without a nonce instead of retrying" do
    attach_session
    stub_request(:get, endpoint).to_return(status: 401, headers: {
                                             "WWW-Authenticate" => 'DPoP error="use_dpop_nonce"'
                                           }, body: "{}")
    expect { client.get_request("app.bsky.actor.getProfile") }.to raise_error(AuthProto::DPoP::Client::Error)
    WebMock.should have_requested(:get, endpoint).times(1)
  end

  it "should reject API errors without a nonce" do
    attach_session
    stub_request(:get, endpoint).to_return(status: 403, headers: { "Content-Type" => "application/json" },
                                           body: '{"error":"Forbidden"}')
    expect { client.get_request("app.bsky.actor.getProfile") }.to raise_error(AuthProto::DPoP::Client::Error,
      /Missing DPoP-Nonce/)
  end

  it "should support fetch_all with separate proofs for each page" do
    attach_session
    proofs = []
    stub_request(:get, endpoint).to_return do |request|
      proofs << request.headers["Dpop"]
      { status: 200, headers: response_headers,
        body: { records: [proofs.length], cursor: proofs.length == 1 ? "next" : nil }.to_json }
    end
    stub_request(:get, endpoint).with(query: { cursor: "next" }).to_return do |request|
      proofs << request.headers["Dpop"]
      { status: 200, headers: response_headers, body: '{"records":[2]}' }
    end
    client.fetch_all("app.bsky.actor.getProfile", field: "records").should == [1, 2]
    proofs.uniq.length.should == 2
  end

  it "should explicitly disable app-password login" do
    expect { client.log_in }.to raise_error(NotImplementedError)
  end

  describe "POST requests" do
    let(:rpc_method) { "com.atproto.repo.createRecord" }
    let(:post_endpoint) { "#{host}/xrpc/#{rpc_method}" }
    let(:record) { { repo: "did:plc:alice", collection: "app.bsky.feed.post", record: { text: "Hello" } } }

    it "should send JSON with a POST proof and accept a successful response without a nonce" do
      attach_session
      expected_headers = {
        "Content-Type" => "application/json", "Authorization" => "DPoP access", "X-Test" => "yes"
      }
      stub_request(:post, post_endpoint).with(body: record.to_json, headers: expected_headers) do |request|
        payload = JWT.decode(request.headers["Dpop"], nil, false).first
        payload["htm"] == "POST" && payload["htu"] == post_endpoint && payload.key?("ath")
      end.to_return(status: 200, headers: { "DPoP-Nonce" => "fixture-nonce",
        "Content-Type" => "application/json" }, body: '{"uri":"at://record"}')

      headers = { "X-Test" => "yes", "authorization" => "Bearer wrong" }
      client.post_request(rpc_method, record, headers: headers)["uri"].should == "at://record"
      headers.should == { "X-Test" => "yes", "authorization" => "Bearer wrong" }
    end

    it "should preserve a binary body, query and custom content type across a nonce retry" do
      attach_session
      binary = "\x00\xFF\x80".b
      proofs = []
      binary_headers = { "Content-Type" => "application/octet-stream" }
      stub_request(:post, post_endpoint).with(query: { test: "yes" }, body: binary,
                                              headers: binary_headers).to_return do |req|
        proofs << req.headers["Dpop"]
        proof = JWT.decode(proofs.last, nil, false).first
        proof["htu"].should == post_endpoint
        if proofs.length == 1
          { status: 401, headers: response_headers("challenge").merge(
            "WWW-Authenticate" => 'DPoP error="use_dpop_nonce"'
          ), body: "{}" }
        else
          proof["nonce"].should == "challenge"
          { status: 200, headers: response_headers("next-nonce"), body: "{}" }
        end
      end

      client.post_request(URI(post_endpoint), binary, params: { test: "yes" },
                                                      headers: { "content-type" => "application/octet-stream" })
      proofs.uniq.length.should == 2
      client.oauth_client.dpop_client.nonce_manager.get(
        server_url: host, session_id: client.session_id
      ).should == "next-nonce"
    end

    it "should refresh an expired token before posting" do
      attach_session(expires_in: -10)
      stub_refresh
      stub_request(:post, post_endpoint).with(headers: { "Authorization" => "DPoP new-access" }, body: record.to_json)
                                        .to_return(status: 200, headers: response_headers, body: "{}")
      client.post_request(rpc_method, record)
    end

    it "should refresh once after an invalid_token rejection and retry the same body" do
      attach_session
      stub_refresh
      stub_request(:post, post_endpoint).with(headers: { "Authorization" => "DPoP access" }, body: record.to_json)
                                        .to_return(status: 401, headers: { "DPoP-Nonce" => "fixture-nonce",
                                                     "WWW-Authenticate" => 'DPoP error="invalid_token"'
                                                   }, body: "{}")
      stub_request(:post, post_endpoint).with(headers: { "Authorization" => "DPoP new-access" }, body: record.to_json)
                                        .to_return(status: 200, headers: response_headers, body: "{}")
      client.post_request(rpc_method, record)
      WebMock.should have_requested(:post, post_endpoint).times(2)
      WebMock.should have_requested(:post, "https://auth.example.com/token").times(1)
    end

    it "should allow unauthenticated JSON posts without a session" do
      stub_request(:post, post_endpoint).with(body: record.to_json) do |request|
        !request.headers.key?("Authorization") && !request.headers.key?("Dpop")
      end.to_return(status: 200, headers: { "DPoP-Nonce" => "fixture-nonce",
        "Content-Type" => "application/json" }, body: "{}")
      client.post_request(rpc_method, record, auth: false).should == {}
    end

    it "should allow an omitted body" do
      attach_session
      stub_request(:post, post_endpoint).with(body: "")
                                        .to_return(status: 200, headers: response_headers, body: "{}")
      client.post_request(rpc_method)
    end

    it "should not retry after a transport timeout" do
      attach_session
      stub_request(:post, post_endpoint).to_timeout
      expect { client.post_request(rpc_method, record) }.to raise_error(Net::OpenTimeout)
      WebMock.should have_requested(:post, post_endpoint).times(1)
    end

    it "should preserve server errors with a nonce without retrying" do
      attach_session
      stub_request(:post, post_endpoint).to_return(status: 500, headers: { "DPoP-Nonce" => "fixture-nonce",
        "Content-Type" => "application/json" },
                                                   body: '{"error":"InternalServerError"}')
      expect { client.post_request(rpc_method, record) }.to raise_error(Minisky::ServerErrorResponse) { |error|
        error.error_type.should == "InternalServerError"
      }
      WebMock.should have_requested(:post, post_endpoint).times(1)
    end
  end
end
