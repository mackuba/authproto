# frozen_string_literal: true

require 'json'
require 'net/http'
require 'resolv'
require 'uri'

require 'atproto_auth/minisky'

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
            metadata: client_metadata
    )
  end
  let(:auth_server) do
    AuthProto::ServerMetadata::AuthorizationServer.new(
      "issuer" => "https://auth.example.com",
      "token_endpoint" => "https://auth.example.com/token",
      "authorization_endpoint" => "https://auth.example.com/authorize",
      "response_types_supported" => "code",
      "grant_types_supported" => %w[authorization_code refresh_token],
      "code_challenge_methods_supported" => "S256",
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
      .to_return(status: 200, body: { authorization_servers: [auth_server.issuer] }.to_json)
    stub_request(:get, "#{auth_server.issuer}/.well-known/oauth-authorization-server")
      .to_return(status: 200, body: auth_server.to_h.to_json)
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
    end.to_return(status: 201, body: { request_uri: "urn:example:par", expires_in: 90 }.to_json)

    result = client.authorize(pds_url: host)
    URI(result[:url]).host.should == "auth.example.com"
    client.session_id.should == result[:session_id]
  end

  it "should submit a native custom-scheme callback unchanged in PAR" do
    callback = "com.example.client:/oauth/callback"
    client_metadata.merge!("application_type" => "native", "token_endpoint_auth_method" => "none",
                           "redirect_uris" => [callback])
    stub_authorization_metadata
    stub_request(:post, "#{auth_server.issuer}/par").with do |request|
      URI.decode_www_form(request.body).to_h["redirect_uri"] == callback
    end.to_return(status: 201, body: { request_uri: "urn:example:par", expires_in: 90 }.to_json)

    URI(client.authorize(pds_url: host)[:url]).host.should == "auth.example.com"
  end

  it "should include a verifiable client assertion when authorizing a confidential client" do
    key = JOSE::JWK.generate_key([:ec, "P-256"])
    key_data = key.to_map.to_h.merge("kid" => "client-key", "use" => "sig")
    client_metadata.merge!("token_endpoint_auth_method" => "private_key_jwt",
                           "token_endpoint_auth_signing_alg" => "ES256", "jwks" => { "keys" => [key_data] })
    stub_authorization_metadata
    public_key = JWT::JWK.import(key.to_public.to_map.to_h).public_key
    stub_request(:post, "#{auth_server.issuer}/par").with do |request|
      form = URI.decode_www_form(request.body).to_h
      payload, header = JWT.decode(form.fetch("client_assertion"), public_key, true, algorithm: "ES256")
      payload["iss"] == client_metadata["client_id"] && payload["aud"] == auth_server.issuer &&
        header["kid"] == "client-key" && form["client_assertion_type"] == AuthProto::PAR::CLIENT_ASSERTION_TYPE
    end.to_return(status: 201, body: { request_uri: "urn:example:par", expires_in: 90 }.to_json)

    client.authorize(pds_url: host)[:url].should include("urn%3Aexample%3Apar")
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
      .to_return(status: 201, body: { request_uri: "urn:example:par", expires_in: 90 }.to_json)

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
        .to_return(status: 201, body: { request_uri: "urn:example:par", expires_in: 90 }.to_json)

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

  it "should delegate login and remember the callback session" do
    client.oauth_client.expects(:authorize).with(handle: "alice.example.com")
          .returns(url: "https://auth.example.com/authorize", session_id: "pending")
    client.authorize(handle: "alice.example.com")[:session_id].should == "pending"
    client.session_id.should == "pending"
    client.oauth_client.expects(:handle_callback).with(code: "code", state: "state", iss: "issuer")
          .returns(session_id: "authorized")
    client.handle_callback(code: "code", state: "state", iss: "issuer")
    client.session_id.should == "authorized"
  end

  it "should sign GETs, preserve params and custom headers, and save successful response nonces" do
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
    client.oauth_client.dpop_client.nonce_manager.get(host).should == "pds-nonce"
  end

  it "should allow unauthenticated requests without a session or nonce header" do
    stub_request(:get, endpoint).with { |request| !request.headers.key?("Authorization") }
                                .to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: "{}")
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

  it "should reuse the persisted DPoP key when refreshing a session from a new client" do
    session = attach_session(expires_in: -10)
    serializer = AuthProto::Serialization::DPoPKey.new
    key_id = AuthProto::Storage::KeyBuilder.dpop_key(client_metadata["client_id"])
    AuthProto.storage.set(key_id, serializer.serialize(client.oauth_client.dpop_client.key_manager))
    restored_key = serializer.deserialize(AuthProto.storage.get(key_id))
    restored = described_class.new(host, client_id: client_metadata["client_id"],
                                  redirect_uri: client_metadata["redirect_uris"].first, metadata: client_metadata,
                                  session_id: session.session_id, dpop_key: restored_key.to_jwk(include_private: true).to_h)
    original_public_key = client.oauth_client.dpop_client.public_key
    stub_refresh
    stub_request(:post, "https://auth.example.com/token").with do |request|
      JWT.decode(request.headers["Dpop"], nil, false).last["jwk"] == original_public_key
    end.to_return(status: 200, body: {
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
          "WWW-Authenticate" => 'DPoP error="use_dpop_nonce"'
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
      "WWW-Authenticate" => 'DPoP error="invalid_token"'
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

  it "should accept successful authenticated responses without a nonce and retain the cached nonce" do
    attach_session
    client.oauth_client.dpop_client.nonce_manager.update(nonce: "cached", server_url: host)
    stub_request(:get, endpoint).to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: "{}")
    client.get_request("app.bsky.actor.getProfile").should == {}
    client.oauth_client.dpop_client.nonce_manager.get(host).should == "cached"
  end

  it "should reject nonce challenges without a nonce instead of retrying" do
    attach_session
    stub_request(:get, endpoint).to_return(status: 401, headers: {
                                             "WWW-Authenticate" => 'DPoP error="use_dpop_nonce"'
                                           }, body: "{}")
    expect { client.get_request("app.bsky.actor.getProfile") }.to raise_error(AuthProto::DPoP::Client::Error)
    WebMock.should have_requested(:get, endpoint).times(1)
  end

  it "should preserve API errors without a nonce" do
    attach_session
    stub_request(:get, endpoint).to_return(status: 403, headers: { "Content-Type" => "application/json" },
                                           body: '{"error":"Forbidden"}')
    expect { client.get_request("app.bsky.actor.getProfile") }.to raise_error(Minisky::ClientErrorResponse) { |error|
      error.error_type.should == "Forbidden"
    }
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
      end.to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: '{"uri":"at://record"}')

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
      client.oauth_client.dpop_client.nonce_manager.get(host).should == "next-nonce"
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
                                        .to_return(status: 401, headers: {
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
      end.to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: "{}")
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

    it "should preserve server errors without retrying or requiring a nonce" do
      attach_session
      stub_request(:post, post_endpoint).to_return(status: 500, headers: { "Content-Type" => "application/json" },
                                                   body: '{"error":"InternalServerError"}')
      expect { client.post_request(rpc_method, record) }.to raise_error(Minisky::ServerErrorResponse) { |error|
        error.error_type.should == "InternalServerError"
      }
      WebMock.should have_requested(:post, post_endpoint).times(1)
    end
  end
end
