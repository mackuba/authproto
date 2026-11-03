# frozen_string_literal: true

require 'jwt'

describe AuthProto::Token::Revocation do
  let(:endpoint) { 'https://auth.example.com/revoke' }
  let(:server) { stub(issuer: 'https://auth.example.com', revocation_endpoint: endpoint) }
  let(:metadata) { stub(client_id: 'https://client.example.com/metadata.json', confidential?: false) }
  let(:session) { AuthProto::State::Session.new(client_id: metadata.client_id, scope: 'atproto', auth_server: server) }
  let(:signer) { nil }
  let(:revoker) do
    described_class.new(session: session, dpop_client: AuthProto::DPoP::Client.new,
                        client_metadata: metadata, client_assertion: signer)
  end

  before do
    AuthProto.configuration.stubs(:http_client).returns(AuthProto::HTTPClient.new)
    AuthProto.stubs(:storage).returns(AuthProto::Storage::Memory.new)
    Resolv::DNS.any_instance.stubs(:getaddresses).returns([Resolv::IPv4.create('93.184.216.34')])
  end

  it "should revoke the refresh token using the session key and fresh proofs after a nonce challenge" do
    proofs = []
    stub_request(:post, endpoint).with do |request|
      session.dpop_key.key.verify(request.headers.fetch('Dpop')).first.should be true
      payload, header = JWT.decode(request.headers.fetch('Dpop'), nil, false)
      header['typ'].should == 'dpop+jwt'
      payload['htu'].should == endpoint
      payload['htm'].should == 'POST'
      payload.should_not have_key('ath')
      proofs << payload
      URI.decode_www_form(request.body).to_h.should == {
        'token' => 'refresh', 'token_type_hint' => 'refresh_token', 'client_id' => metadata.client_id
      }
    end.to_return(
      { status: 400, headers: { 'DPoP-Nonce' => 'challenge' }, body: '{"error":"use_dpop_nonce"}' },
      { status: 200, headers: { 'DPoP-Nonce' => 'success' } }
    )

    revoker.revoke_token('refresh', token_type: 'refresh_token')

    proofs.length.should == 2
    proofs.map { |proof| proof['jti'] }.uniq.length.should == 2
    proofs.last['nonce'].should == 'challenge'
  end

  it "should authenticate confidential revocation with the client key and issuer audience" do
    key = JOSE::JWK.generate_key([:ec, 'P-256']).to_map.to_h.merge('kid' => 'client-key')
    assertion = AuthProto::PAR::ClientAssertion.new(client_id: metadata.client_id, signing_key: key)
    metadata.stubs(:confidential?).returns(true)
    revoker = described_class.new(session: session, dpop_client: AuthProto::DPoP::Client.new,
                                 client_metadata: metadata, client_assertion: assertion)
    stub_request(:post, endpoint).with do |request|
      form = URI.decode_www_form(request.body).to_h
      form['client_assertion_type'].should == AuthProto::PAR::CLIENT_ASSERTION_TYPE
      payload, header = JWT.decode(form.fetch('client_assertion'), JWT::JWK.import(key).public_key,
                                   true, algorithms: ['ES256'])
      payload['aud'].should == server.issuer
      payload['sub'].should == metadata.client_id
      header['kid'].should == 'client-key'
    end.to_return(status: 200, headers: { 'DPoP-Nonce' => 'nonce' })

    revoker.revoke_token('refresh', token_type: 'refresh_token')

    assert_requested :post, endpoint, times: 1
  end

  it "should report when the server has no revocation endpoint" do
    server.stubs(:revocation_endpoint).returns(nil)

    expect {
      revoker.revoke_token('refresh', token_type: 'refresh_token')
    }.to raise_error(described_class::Error, /revocation endpoint/)

    assert_not_requested :post, endpoint
  end

  [nil, '', false].each do |token|
    it "should reject an invalid refresh token #{token.inspect}" do
      expect { revoker.revoke_token(token, token_type: 'refresh_token') }.to raise_error(ArgumentError)
      assert_not_requested :post, endpoint
    end
  end

  it "should propagate transport failures" do
    stub_request(:post, endpoint).to_raise(IOError)

    expect {
      revoker.revoke_token('refresh', token_type: 'refresh_token')
    }.to raise_error(AuthProto::HTTPClient::HTTPError)
  end

  [400, 401, 503].each do |status|
    it "should report HTTP #{status} rather than treating revocation as successful" do
      stub_request(:post, endpoint).to_return(status: status, headers: { 'DPoP-Nonce' => 'nonce' })

      expect {
        revoker.revoke_token('refresh', token_type: 'refresh_token')
      }.to raise_error(described_class::Error, /HTTP #{status}/)
    end
  end

  ['access_token', :access_token, 'refresh_token', :refresh_token].each do |type|
    it "should accept #{type.inspect} and send a string hint while ignoring the successful response body" do
      stub_request(:post, endpoint).with(body: {
        token: 'token', token_type_hint: type.to_s, client_id: metadata.client_id
      }).to_return(status: 200, headers: { 'DPoP-Nonce' => 'nonce' }, body: 'not JSON')

      revoker.revoke_token('token', token_type: type).should be_nil
    end
  end

  [nil, false, 123, 'invalid', :invalid].each do |type|
    it "should reject invalid token type #{type.inspect} before making a request" do
      expect { revoker.revoke_token('token', token_type: type) }.to raise_error(ArgumentError, /Invalid token_type/)

      assert_not_requested :post, endpoint
    end
  end

  it "should propagate a missing nonce error" do
    stub_request(:post, endpoint).to_return(status: 200)

    expect {
      revoker.revoke_token('refresh', token_type: 'refresh_token')
    }.to raise_error(AuthProto::DPoP::Client::Error)
  end
end
