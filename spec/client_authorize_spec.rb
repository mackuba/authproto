# frozen_string_literal: true

describe AuthProto::Client, 'authorization inputs' do
  let(:client) { described_class.new(client_id: 'http://localhost', redirect_uri: 'http://127.0.0.1/') }

  ['pds.example.com', 'pds.example.com:443', URI('pds.example.com')].each do |pds|
    it "should reject a PDS hostname before discovery or session creation: #{pds}" do
      AuthProto::Metadata::ResourceServer.expects(:from_url).never
      client.session_manager.expects(:create_session).never

      expect { client.authorize(pds: pds) }.to raise_error(ArgumentError, "pds must be a full URL")
    end
  end

  it "should accept a PDS URI and store its string form in the session" do
    pds = URI('https://pds.example.com').freeze
    server = mock('authorization server')
    session = mock('session', session_id: 'session-1')
    client.expects(:resolve_auth_server_info).with(pds.to_s).returns(server)
    client.session_manager.expects(:create_session).with(
      client_id: client.client_id, scope: 'atproto', auth_server: server,
      did: nil, pds: pds.to_s, signing_key_id: nil
    ).returns(session)
    client.expects(:submit_authorization_par).with(server, session, login_hint: nil).returns('https://auth.example.com')

    client.authorize(pds: pds).should == { url: 'https://auth.example.com', session_id: 'session-1' }
  end
end
