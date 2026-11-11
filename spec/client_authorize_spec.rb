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
    client.expects(:submit_authorization_par).with(server, session, login_hint: nil, prompt: nil)
          .returns('https://auth.example.com')

    client.authorize(pds: pds).should == { url: 'https://auth.example.com', session_id: 'session-1' }
  end

  describe 'prompt' do
    let(:pds) { 'https://pds.example.com' }
    let(:issuer) { 'https://auth.example.com' }
    let(:server) do
      stub('authorization server', issuer: issuer, pushed_authorization_request_endpoint: "#{issuer}/par",
                                   authorization_endpoint: "#{issuer}/authorize")
    end

    ['', :consent].each do |prompt|
      it "should reject an invalid prompt: #{prompt.inspect}" do
        server.stubs(:prompt_values_supported).returns(['consent', 'login'])
        client.stubs(:resolve_auth_server_info).with(pds).returns(server)
        client.session_manager.expects(:create_session).never

        expect { client.authorize(pds: pds, prompt: prompt) }.to raise_error(ArgumentError, /nonempty string/)
      end
    end

    [%w[login], []].each do |supported_prompts|
      it "should reject a prompt absent from #{supported_prompts.inspect} before creating a session" do
        server.stubs(:prompt_values_supported).returns(supported_prompts)
        client.stubs(:resolve_auth_server_info).with(pds).returns(server)
        client.session_manager.expects(:create_session).never

        expect { client.authorize(pds: pds, prompt: 'consent') }.to raise_error(ArgumentError, /not supported/)
      end
    end

    [
      ['consent', %w[login consent]],
      ['custom_prompt', nil],
      [nil, []]
    ].each do |prompt, supported_prompts|
      it "should submit PAR with prompt #{prompt.inspect} when the advertised list is #{supported_prompts.inspect}" do
        server.stubs(:prompt_values_supported).returns(supported_prompts)
        client.stubs(:resolve_auth_server_info).with(pds).returns(server)
        session = AuthProto::State::Session.new(client_id: client.client_id, scope: 'atproto')
        client.session_manager.expects(:create_session).returns(session)
        http_client = mock('HTTP client')
        AuthProto.configuration.stubs(:http_client).returns(http_client)
        http_client.expects(:post).with { |url, options|
          form = URI.decode_www_form(options.fetch(:body)).to_h
          url == "#{issuer}/par" && (prompt.nil? ? !form.key?('prompt') : form['prompt'] == prompt)
        }.returns(status: 201, headers: { 'content-type' => 'application/json', 'dpop-nonce' => 'test-nonce' },
                  body: '{"request_uri":"urn:example:request","expires_in":60}')

        result = client.authorize(pds: pds, prompt: prompt)
        URI.decode_www_form(URI(result.fetch(:url)).query).to_h.should == {
          'client_id' => client.client_id, 'request_uri' => 'urn:example:request'
        }
      end
    end
  end
end
