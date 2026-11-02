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

    revoker.revoke_refresh_token('refresh')

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

    revoker.revoke_refresh_token('refresh')

    assert_requested :post, endpoint, times: 1
  end

  it "should skip revocation when the server has no revocation endpoint" do
    server.stubs(:revocation_endpoint).returns(nil)

    revoker.revoke_refresh_token('refresh')

    assert_not_requested :post, endpoint
  end

  [nil, '', false].each do |token|
    it "should skip revocation for an absent or invalid refresh token #{token.inspect}" do
      revoker.revoke_refresh_token(token)

      assert_not_requested :post, endpoint
    end
  end

  it "should ignore transport failures" do
    stub_request(:post, endpoint).to_raise(IOError)

    revoker.revoke_refresh_token('refresh').should be_nil
  end
end
