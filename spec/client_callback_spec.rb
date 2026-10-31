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
    client.session_manager.create_session(client_id: client.client_id, scope: 'atproto', auth_server: auth_server)
  end
  let(:callback) { { code: 'code', state: session.state_token, iss: auth_server.issuer } }

  before do
    AuthProto.stubs(:storage).returns(storage)
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
    client.expects(:exchange_code).returns(
      'access_token' => 'access', 'refresh_token' => 'refresh', 'token_type' => 'DPoP',
      'expires_in' => 3600, 'scope' => 'atproto', 'sub' => 'did:plc:alice'
    )
    state = session.state_token

    result = client.handle_callback(**callback, expected_session_id: session.session_id)

    result[:session_id].should == session.session_id
    result[:access_token].should == 'access'
    client.session_manager.get_session(session.session_id).should be_authorized
    client.session_manager.get_session_by_state_token(state).should be_nil
  end
end
