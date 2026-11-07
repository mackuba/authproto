# frozen_string_literal: true

describe AuthProto::Client, 'sessions' do
  let(:client) do
    AuthProto::Client.new(client_id: 'http://localhost/', redirect_uri: 'http://127.0.0.1/')
  end
  let(:storage) { AuthProto::Storage::Memory.new }
  let(:other_client) do
    AuthProto::Client.new(client_id: 'http://localhost/?scope=atproto', redirect_uri: 'http://127.0.0.1/')
  end

  before do
    AuthProto.stubs(:storage).returns(storage)
  end

  it "should remove both the pending session and its state lookup" do
    session = client.session_manager.create_session(client_id: client.client_id, scope: 'atproto')
    session_key = AuthProto::Storage::KeyBuilder.session_key(session.session_id)
    state_key = AuthProto::Storage::KeyBuilder.state_key(session.state_token)

    client.delete_session(session.session_id)

    storage.exists?(session_key).should be_falsey
    storage.exists?(state_key).should be_falsey
  end

  it "should delete a pending session without attempting revocation even when requested" do
    session = client.session_manager.create_session(client_id: client.client_id, scope: 'atproto')
    state_key = AuthProto::Storage::KeyBuilder.state_key(session.state_token)
    client.instance_variable_get(:@dpop_client).expects(:generate_proof).never

    client.delete_session(session.session_id, revoke: true)

    client.session_manager.get_session(session.session_id).should be_nil
    storage.exists?(state_key).should be_falsey
  end

  it "should reject a refresh if the session was deleted while it was waiting for its lock" do
    session = client.session_manager.create_session(client_id: client.client_id, scope: 'atproto')
    session.tokens = AuthProto::State::TokenSet.new(
      access_token: 'access', refresh_token: 'refresh', token_type: 'DPoP',
      expires_in: 3600, scope: 'atproto', sub: 'did:plc:alice'
    )
    client.session_manager.complete_authorization(session)
    session_key = AuthProto::Storage::KeyBuilder.session_key(session.session_id)
    lock_key = AuthProto::Storage::KeyBuilder.lock_key('session', session.session_id)
    client.instance_variable_get(:@dpop_client).expects(:generate_proof).never
    storage.expects(:with_lock).with(lock_key, ttl: 30) do
      storage.delete(session_key)
      true
    end.yields

    expect { client.refresh_token(session.session_id) }.to raise_error(AuthProto::Client::TokenError, "Invalid session")

    storage.exists?(session_key).should be_falsey
  end

  it "should reject a callback belonging to another client before exchanging the code" do
    session = other_client.session_manager.create_session(client_id: other_client.client_id, scope: 'atproto')
    client.expects(:exchange_code).never

    expect {
      client.handle_callback({ code: 'code', state: session.state_token, iss: 'https://auth.example.com' },
                             expected_session_id: session.session_id)
    }.to raise_error(AuthProto::Client::CallbackError, "Invalid state parameter")

    other_client.session_manager.get_session_by_state_token(session.state_token).should be_pending
  end

  it "should prevent token retrieval, proofs, refresh and deletion through a different client" do
    session = other_client.session_manager.create_session(client_id: other_client.client_id, scope: 'atproto')
    session.tokens = AuthProto::State::TokenSet.new(
      access_token: 'access', refresh_token: 'refresh', token_type: 'DPoP',
      expires_in: 3600, scope: 'atproto', sub: 'did:plc:alice'
    )
    other_client.session_manager.complete_authorization(session)
    client.instance_variable_get(:@dpop_client).expects(:generate_proof).never

    client.get_tokens(session.session_id).should be_nil
    client.authorized?(session.session_id).should be false
    expect {
      client.auth_headers(session_id: session.session_id, method: 'GET', url: 'https://pds.example.com/xrpc/test')
    }.to raise_error(AuthProto::Client::TokenError, "Invalid session")
    expect {
      client.refresh_token(session.session_id)
    }.to raise_error(AuthProto::Client::TokenError, "Invalid session")
    client.delete_session(session.session_id)

    other_client.get_tokens(session.session_id)[:access_token].should == 'access'
    client.delete_session(session.session_id, revoke: true)
    other_client.session_manager.get_session(session.session_id).client_id.should == other_client.client_id
  end

  describe 'token revocation on deletion' do
    let(:endpoint) { 'https://auth.example.com/revoke' }
    let(:session) do
      session = client.session_manager.create_session(client_id: client.client_id, scope: 'atproto')
      session.tokens = AuthProto::State::TokenSet.new(
        access_token: 'access', refresh_token: 'refresh', token_type: 'DPoP',
        expires_in: 3600, scope: 'atproto', sub: 'did:plc:alice'
      )
      client.session_manager.complete_authorization(session)
      session
    end

    before do
      AuthProto.configuration.stubs(:http_client).returns(AuthProto::HTTPClient.new)
      Resolv::DNS.any_instance.stubs(:getaddresses).returns([Resolv::IPv4.create('93.184.216.34')])
      manager = client.session_manager
      manager.stubs(:get_session).with(session.session_id).returns(session)
      session.stubs(:auth_server).returns(stub(issuer: 'https://auth.example.com', revocation_endpoint: endpoint))
    end

    it "should revoke both tokens before removing the local session" do
      requests = []
      stub_request(:post, endpoint).to_return do |request|
        storage.exists?(AuthProto::Storage::KeyBuilder.session_key(session.session_id)).should be_truthy
        requests << URI.decode_www_form(request.body).to_h
        { status: 200, headers: { 'DPoP-Nonce' => 'nonce' } }
      end

      client.delete_session(session.session_id, revoke: true)

      requests.map { |body| [body['token'], body['token_type_hint']] }.should == [
        ['refresh', 'refresh_token'], ['access', 'access_token']
      ]
      storage.exists?(AuthProto::Storage::KeyBuilder.session_key(session.session_id)).should be_falsey
    end

    it "should delete locally without contacting the server by default" do
      client.instance_variable_get(:@dpop_client).expects(:generate_proof).never

      client.delete_session(session.session_id)

      storage.exists?(AuthProto::Storage::KeyBuilder.session_key(session.session_id)).should be_falsey
    end

    it "should revoke the access token when no refresh token was issued" do
      session.tokens = AuthProto::State::TokenSet.new(
        access_token: 'access', token_type: 'DPoP', expires_in: 3600, scope: 'atproto', sub: 'did:plc:alice'
      )
      stub_request(:post, endpoint).with(body: {
        token: 'access', token_type_hint: 'access_token', client_id: client.client_id
      }).to_return(status: 200, headers: { 'DPoP-Nonce' => 'nonce' })

      client.delete_session(session.session_id, revoke: true)

      assert_requested :post, endpoint, times: 1
    end

    it "should skip revocation and delete locally when the server has no revocation endpoint" do
      session.auth_server.stubs(:revocation_endpoint).returns(nil)
      client.instance_variable_get(:@dpop_client).expects(:generate_proof).never

      client.delete_session(session.session_id, revoke: true)

      storage.exists?(AuthProto::Storage::KeyBuilder.session_key(session.session_id)).should be_falsey
    end

    it "should propagate a transport failure and allow explicit local deletion afterwards" do
      stub_request(:post, endpoint).to_raise(IOError)

      expect {
        client.delete_session(session.session_id, revoke: true)
      }.to raise_error(AuthProto::HTTPClient::HTTPError)

      storage.exists?(AuthProto::Storage::KeyBuilder.session_key(session.session_id)).should be_truthy
      client.delete_session(session.session_id, revoke: false)
      storage.exists?(AuthProto::Storage::KeyBuilder.session_key(session.session_id)).should be_falsey
    end

    [
      { status: 400, headers: { 'DPoP-Nonce' => 'nonce' }, body: '{"error":"unsupported_token_type"}' },
      { status: 503, headers: { 'DPoP-Nonce' => 'nonce' } },
      { status: 200, headers: {} }
    ].each do |failure|
      it "should delete locally after refresh revocation despite access-token revocation failure #{failure.inspect}" do
        stub_request(:post, endpoint).to_return(
          { status: 200, headers: { 'DPoP-Nonce' => 'nonce' } }, failure
        )

        client.delete_session(session.session_id, revoke: true)

        storage.exists?(AuthProto::Storage::KeyBuilder.session_key(session.session_id)).should be_falsey
        assert_requested :post, endpoint, times: 2
      end
    end

    it "should delete locally after refresh revocation despite an access-token transport failure" do
      stub_request(:post, endpoint).to_return(
        status: 200, headers: { 'DPoP-Nonce' => 'nonce' }
      ).then.to_raise(IOError)

      client.delete_session(session.session_id, revoke: true)

      storage.exists?(AuthProto::Storage::KeyBuilder.session_key(session.session_id)).should be_falsey
      assert_requested :post, endpoint, times: 2
    end

    it "should preserve the session and skip access-token revocation if refresh-token revocation fails" do
      stub_request(:post, endpoint).to_return(
        status: 503, headers: { 'DPoP-Nonce' => 'nonce' }
      )

      expect {
        client.delete_session(session.session_id, revoke: true)
      }.to raise_error(AuthProto::Token::Revocation::Error, /HTTP 503/)

      storage.exists?(AuthProto::Storage::KeyBuilder.session_key(session.session_id)).should be_truthy
      assert_requested :post, endpoint, times: 1
    end

    it "should propagate access-token revocation failures and preserve the session when there is no refresh token" do
      session.tokens = AuthProto::State::TokenSet.new(
        access_token: 'access', token_type: 'DPoP', expires_in: 3600, scope: 'atproto', sub: 'did:plc:alice'
      )
      stub_request(:post, endpoint).to_return(status: 503, headers: { 'DPoP-Nonce' => 'nonce' })

      expect {
        client.delete_session(session.session_id, revoke: true)
      }.to raise_error(AuthProto::Token::Revocation::Error, /HTTP 503/)

      storage.exists?(AuthProto::Storage::KeyBuilder.session_key(session.session_id)).should be_truthy
      assert_requested :post, endpoint, times: 1
    end
  end
end
