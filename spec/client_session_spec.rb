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

  it "should reject a callback belonging to another client before exchanging the code" do
    session = other_client.session_manager.create_session(client_id: other_client.client_id, scope: 'atproto')
    client.expects(:exchange_code).never

    expect {
      client.handle_callback(code: 'code', state: session.state_token, iss: 'https://auth.example.com',
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
    client.dpop_client.expects(:generate_proof).never

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
    other_client.session_manager.get_session(session.session_id).client_id.should == other_client.client_id
  end
end
