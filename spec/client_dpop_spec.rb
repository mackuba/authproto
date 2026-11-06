# frozen_string_literal: true

require 'json'

describe AuthProto::Client, 'DPoP' do
  let(:client) { described_class.new(client_id: 'http://localhost', redirect_uri: 'http://127.0.0.1/') }
  let(:url) { 'https://pds.example.com/xrpc/app.bsky.actor.getProfile' }
  let(:session) do
    session = client.session_manager.create_session(client_id: client.client_id, scope: 'atproto')
    session.tokens = AuthProto::State::TokenSet.new(
      access_token: 'access', token_type: 'DPoP', expires_in: 3600, scope: 'atproto', sub: 'did:plc:alice'
    )
    client.session_manager.complete_authorization(session)
    session
  end
  let(:challenge) do
    { status: 401, headers: { 'DPoP-Nonce' => 'challenge', 'WWW-Authenticate' => 'DPoP error="use_dpop_nonce"' },
      body: nil }
  end
  let(:success) { { status: 200, headers: { 'DPoP-Nonce' => 'next' }, body: '{}' } }

  before do
    AuthProto.stubs(:storage).returns(AuthProto::Storage::Memory.new)
  end

  context "with URI objects" do
    let(:url) { URI('https://pds.example.com/xrpc/app.bsky.actor.getProfile?limit=1').freeze }

    it "should process response nonces and generate proofs through the public client methods" do
      client.process_dpop(success, url: url, session_id: session.session_id)
      proof_payload.fetch('nonce').should == 'next'
      proof_payload.fetch('htu').should == 'https://pds.example.com/xrpc/app.bsky.actor.getProfile'

      client.with_nonce_handling(session.session_id, url) { success }.should equal(success)
      url.query.should == 'limit=1'
    end
  end

  it "should use the nonce from process_dpop in the next authorization headers" do
    client.process_dpop(success, url: url, session_id: session.session_id)

    proof_payload.fetch('nonce').should == 'next'
  end

  it "should distinguish a nonce challenge from a successful response with a nonce" do
    client.has_nonce_error?(challenge).should be true
    client.has_nonce_error?(success).should be false
  end

  it "should retry a nonce challenge with fresh authorization headers using only the session ID" do
    responses = [challenge, success]
    proofs = []

    result = client.with_nonce_handling(session.session_id, url) do
      proofs << proof_payload
      responses.shift
    end

    result.should equal(success)
    proofs.length.should == 2
    proofs.first.should_not have_key('nonce')
    proofs.last.fetch('nonce').should == 'challenge'
    proofs.last.fetch('jti').should_not == proofs.first.fetch('jti')
    proof_payload.fetch('nonce').should == 'next'
  end

  def proof_payload
    headers = client.auth_headers(session_id: session.session_id, method: 'GET', url: url)
    verified, payload = session.dpop_key.key.verify(headers.fetch('DPoP'))
    verified.should be true
    JSON.parse(payload)
  end
end
