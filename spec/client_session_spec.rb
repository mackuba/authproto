# frozen_string_literal: true

describe AuthProto::Client, '#delete_session' do
  let(:client) do
    AuthProto::Client.new(client_id: 'http://localhost/', redirect_uri: 'http://127.0.0.1/')
  end
  let(:storage) { AuthProto::Storage::Memory.new }

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
end
