# frozen_string_literal: true

describe AuthProto::Client, '#handle_callback' do
  let(:client) do
    AuthProto::Client.new(client_id: 'http://localhost/', redirect_uri: 'http://127.0.0.1/')
  end
  let(:storage) { AuthProto::Storage::Memory.new }
  let(:auth_server) do
    AuthProto::Metadata::AuthorizationServer.new(
      'issuer' => 'https://auth.example.com',
      'token_endpoint' => 'https://auth.example.com/token',
      'revocation_endpoint' => 'https://auth.example.com/revoke',
      'authorization_endpoint' => 'https://auth.example.com/authorize',
      'response_types_supported' => ['code'],
      'grant_types_supported' => %w[authorization_code refresh_token],
      'code_challenge_methods_supported' => ['S256'],
      'token_endpoint_auth_methods_supported' => %w[private_key_jwt none],
      'token_endpoint_auth_signing_alg_values_supported' => ['ES256'],
      'scopes_supported' => ['atproto'],
      'dpop_signing_alg_values_supported' => ['ES256'],
      'pushed_authorization_request_endpoint' => 'https://auth.example.com/par',
      'authorization_response_iss_parameter_supported' => true,
      'require_pushed_authorization_requests' => true,
      'client_id_metadata_document_supported' => true
    )
  end
  let(:session) do
    client.session_manager.create_session(
      client_id: client.client_id, scope: 'atproto', auth_server: auth_server, did: 'did:plc:alice'
    )
  end
  let(:callback) { { code: 'code', state: session.state_token, iss: auth_server.issuer } }

  before do
    AuthProto.stubs(:storage).returns(storage)
    AuthProto.configuration.stubs(:http_client).returns(AuthProto::HTTPClient.new)
    Resolv::DNS.any_instance.stubs(:getaddresses).returns([Resolv::IPv4.create('93.184.216.34')])
    stub_request(:post, 'https://auth.example.com/revoke').to_return(
      status: 200, headers: { 'DPoP-Nonce' => 'revoke-nonce' }
    )
  end

  [{ headers: {} }, { headers: { 'Content-Type' => 'text/html' } }, { body: '[]' },
   { expires_in: 0 }, { access_token: 123 }, { refresh_token: '' }].each do |invalid_response|
    it "should reject malformed code exchange responses #{invalid_response.inspect} without completing authorization" do
      data = {
        access_token: 'access', refresh_token: 'refresh', token_type: 'DPoP',
        expires_in: 3600, scope: 'atproto', sub: 'did:plc:alice'
      }.merge(invalid_response.except(:headers, :body))
      response = {
        status: 200, headers: { 'Content-Type' => 'application/json' }, body: data.to_json
      }.merge(invalid_response.slice(:headers, :body))
      response[:headers]['DPoP-Nonce'] = 'nonce'
      client.stubs(:make_token_request).returns(response)

      expect {
        client.handle_callback(**callback, expected_session_id: session.session_id)
      }.to raise_error(AuthProto::Client::TokenError)

      client.session_manager.get_session_by_state_token(session.state_token).should be_pending
    end
  end

  ['dpop', 'DPOP', 'dPoP'].each do |type|
    it "should accept token_type #{type} from code exchange and persist its canonical spelling" do
      client.expects(:make_token_request).with('code', anything).returns(
        status: 200, headers: { 'Content-Type' => 'application/json', 'DPoP-Nonce' => 'nonce' }, body: {
          access_token: 'access', refresh_token: 'refresh', token_type: type,
          expires_in: 3600, scope: 'atproto', sub: 'did:plc:alice'
        }.to_json
      )

      result = client.handle_callback(**callback, expected_session_id: session.session_id)

      result[:token_type].should == 'DPoP'
      client.session_manager.get_session(session.session_id).tokens.token_type.should == 'DPoP'
    end
  end

  it "should require the expected session ID keyword before exchanging the code" do
    client.expects(:exchange_code).never

    expect {
      client.handle_callback(**callback)
    }.to raise_error(ArgumentError, /missing keyword: :expected_session_id/)
  end

  [nil, '', 123].each do |expected_session_id|
    it "should reject an invalid expected session ID #{expected_session_id.inspect} without consuming state" do
      client.expects(:exchange_code).never

      expect {
        client.handle_callback(**callback, expected_session_id: expected_session_id)
      }.to raise_error(AuthProto::Client::CallbackError, "Expected session ID is required")

      client.session_manager.get_session_by_state_token(session.state_token).session_id.should == session.session_id
    end
  end

  it "should reject a valid callback from a different browser's authorization attempt before code exchange" do
    other_session = client.session_manager.create_session(
      client_id: client.client_id, scope: 'atproto', auth_server: auth_server
    )
    client.expects(:exchange_code).never

    expect {
      client.handle_callback(**callback, expected_session_id: other_session.session_id)
    }.to raise_error(AuthProto::Client::CallbackError, "Session ID mismatch")

    client.session_manager.get_session_by_state_token(session.state_token).should be_pending
    client.session_manager.get_session_by_state_token(other_session.state_token).should be_pending
  end

  it "should still reject an unknown state when the expected session ID is present" do
    client.expects(:exchange_code).never

    expect {
      client.handle_callback(**callback.merge(state: 'unknown'), expected_session_id: session.session_id)
    }.to raise_error(AuthProto::Client::CallbackError, "Invalid state parameter")
  end

  it "should still reject the wrong issuer when the expected session matches" do
    client.expects(:exchange_code).never

    expect {
      client.handle_callback(
        **callback.merge(iss: 'https://other.example.com'), expected_session_id: session.session_id
      )
    }.to raise_error(AuthProto::Client::CallbackError, "Issuer mismatch")
  end

  it "should complete authorization and consume state when the expected session matches" do
    client.expects(:exchange_code).returns(AuthProto::State::TokenSet.new(
      access_token: 'access', refresh_token: 'refresh', token_type: 'DPoP',
      expires_in: 3600, scope: 'atproto', sub: 'did:plc:alice'
    ))
    state = session.state_token

    result = client.handle_callback(**callback, expected_session_id: session.session_id)

    result[:session_id].should == session.session_id
    result[:access_token].should == 'access'
    client.session_manager.get_session(session.session_id).should be_authorized
    client.session_manager.get_session_by_state_token(state).should be_nil
  end

  it "should revoke the received refresh token when the subject differs from the expected DID" do
    client.stubs(:make_token_request).returns(
      status: 200, headers: { 'Content-Type' => 'application/json', 'DPoP-Nonce' => 'nonce' }, body: {
        access_token: 'access', refresh_token: 'rejected-refresh', token_type: 'DPoP',
        expires_in: 3600, scope: 'atproto', sub: 'did:plc:someone-else'
      }.to_json
    )

    expect {
      client.handle_callback(**callback, expected_session_id: session.session_id)
    }.to raise_error(AuthProto::Client::TokenError, "Subject mismatch in token response")

    assert_requested :post, 'https://auth.example.com/revoke', body: {
      token: 'rejected-refresh', token_type_hint: 'refresh_token', client_id: client.client_id
    }
    client.session_manager.get_session_by_state_token(session.state_token).should be_pending
  end

  it "should persist and expose a reduced grant when completing authorization" do
    pending = client.session_manager.create_session(
      client_id: client.client_id, scope: 'atproto transition:email',
      auth_server: auth_server, did: 'did:plc:alice'
    )
    client.stubs(:make_token_request).returns(
      status: 200, headers: { 'Content-Type' => 'application/json', 'DPoP-Nonce' => 'nonce' }, body: {
        access_token: 'access', refresh_token: 'refresh', token_type: 'DPoP',
        expires_in: 3600, scope: 'atproto', sub: 'did:plc:alice'
      }.to_json
    )

    result = client.handle_callback(code: 'code', state: pending.state_token, iss: auth_server.issuer,
                                    expected_session_id: pending.session_id)
    restored = client.session_manager.get_session(pending.session_id)

    result[:granted_scope].should == 'atproto'
    restored.scope.should == 'atproto transition:email'
    restored.granted_scope.should == 'atproto'
    restored.has_limited_scope?.should be true
  end

  it "should preserve the subject mismatch error if revocation fails" do
    client.stubs(:make_token_request).returns(
      status: 200, headers: { 'Content-Type' => 'application/json', 'DPoP-Nonce' => 'nonce' }, body: {
        access_token: 'access', refresh_token: 'rejected-refresh', token_type: 'DPoP',
        expires_in: 3600, scope: 'atproto', sub: 'did:plc:someone-else'
      }.to_json
    )
    stub_request(:post, 'https://auth.example.com/revoke').to_raise(IOError)

    expect {
      client.handle_callback(**callback, expected_session_id: session.session_id)
    }.to raise_error(AuthProto::Client::TokenError, "Subject mismatch in token response")
  end

  describe "when authorization starts with a PDS" do
    let(:pds) { 'https://pds.example.com' }
    let(:subject) { 'did:plc:ewvi7nxzyoun6zhxrhs64oiz' }
    let(:session) do
      client.session_manager.create_session(
        client_id: client.client_id, scope: 'atproto', auth_server: auth_server, pds: pds
      )
    end

    before do
      client.stubs(:make_token_request).returns(
        status: 200, headers: { 'Content-Type' => 'application/json', 'DPoP-Nonce' => 'nonce' }, body: {
          access_token: 'access', refresh_token: 'refresh', token_type: 'DPoP',
          expires_in: 3600, scope: 'atproto', sub: subject
        }.to_json
      )
    end

    it "should persist the PDS used for authorization server discovery" do
      client.expects(:resolve_auth_server_info).with(pds).returns(auth_server)
      client.stubs(:submit_authorization_par).returns('https://auth.example.com/authorize')

      result = client.authorize(pds: pds)

      client.session_manager.get_session(result[:session_id]).pds.should == pds
    end

    [
      'https://pds.example.com',
      'https://pds.example.com/',
      'https://PDS.EXAMPLE.COM:443/'
    ].each do |endpoint|
      it "should accept a subject hosted at #{endpoint}" do
        document = stub(pds_endpoint: endpoint)
        DIDKit::DID.expects(:new).with(subject).returns(stub(document: document))

        result = client.handle_callback(**callback, expected_session_id: session.session_id)

        result[:did].should == subject
        client.session_manager.get_session(session.session_id).should be_authorized
      end
    end

    ['https://other.example.com', 'https://pds.example.com:8443', 'http://pds.example.com'].each do |endpoint|
      it "should reject a subject whose PDS is #{endpoint.inspect} without completing authorization" do
        document = stub(pds_endpoint: endpoint)
        DIDKit::DID.expects(:new).with(subject).returns(stub(document: document))

        expect {
          client.handle_callback(**callback, expected_session_id: session.session_id)
        }.to raise_error(AuthProto::Client::TokenError, "Subject PDS does not match session PDS")

        client.session_manager.get_session_by_state_token(session.state_token).should be_pending
        assert_requested :post, 'https://auth.example.com/revoke', body: {
          token: 'refresh', token_type_hint: 'refresh_token', client_id: client.client_id
        }
      end
    end

    it "should reject an invalid subject DID without completing authorization" do
      DIDKit::DID.expects(:new).with(subject).raises(DIDKit::DIDError, "Invalid DID")

      expect {
        client.handle_callback(**callback, expected_session_id: session.session_id)
      }.to raise_error(AuthProto::Client::TokenError, /Invalid token subject/)

      client.session_manager.get_session_by_state_token(session.state_token).should be_pending
    end

    it "should leave authorization pending if DID resolution fails" do
      did = mock
      did.expects(:document).raises(IOError, "Connection failed")
      DIDKit::DID.expects(:new).with(subject).returns(did)

      expect {
        client.handle_callback(**callback, expected_session_id: session.session_id)
      }.to raise_error(AuthProto::Client::TokenError, /Connection failed; start authorization again/)

      client.session_manager.get_session_by_state_token(session.state_token).should be_pending
      assert_not_requested :post, 'https://auth.example.com/revoke'
    end

    it "should reject an older pending session without a stored PDS" do
      old_session = client.session_manager.create_session(
        client_id: client.client_id, scope: 'atproto', auth_server: auth_server
      )
      DIDKit::DID.expects(:new).never

      expect {
        client.handle_callback(code: 'code', state: old_session.state_token, iss: auth_server.issuer,
                               expected_session_id: old_session.session_id)
      }.to raise_error(AuthProto::Client::TokenError, /missing its PDS/)
    end
  end
end
