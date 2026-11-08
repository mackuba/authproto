# frozen_string_literal: true

describe AuthProto::State::SessionInfo do
  let(:now) { Time.utc(2026, 1, 1) }
  let(:server) { stub(issuer: 'https://auth.example.com', revocation_endpoint: 'https://auth.example.com/revoke') }
  let(:session) do
    AuthProto::State::Session.new(
      client_id: 'https://client.example.com/metadata.json', scope: 'atproto repo:app.bsky.feed.post',
      auth_server: server, pds: 'https://pds.example.com'
    )
  end
  let(:tokens) do
    AuthProto::State::TokenSet.new(
      access_token: +'access', refresh_token: +'refresh', token_type: 'DPoP',
      expires_in: 3600, scope: +'atproto', sub: +'did:plc:alice'
    )
  end

  before do
    Time.stubs(:now).returns(now)
  end

  it "should expose all public session data and predicates through a live view" do
    session.tokens = tokens
    info = described_class.new(session)

    info.to_h.should == {
      access_token: 'access', expires_in: 3600, expires_at: now + 3600, refresh_token: 'refresh',
      requested_scope: 'atproto repo:app.bsky.feed.post', granted_scope: 'atproto',
      session_id: session.session_id, did: 'did:plc:alice', pds: 'https://pds.example.com'
    }
    info.access_token.should == 'access'
    info.expires_in.should == 3600
    info.expires_at.should == now + 3600
    info.refresh_token.should == 'refresh'
    info.requested_scope.should == session.requested_scope
    info.granted_scope.should == 'atproto'
    info.session_id.should == session.session_id
    info.did.should == 'did:plc:alice'
    info.pds.should == 'https://pds.example.com'
    info.should be_has_limited_scope
    info.should_not be_pending
    info.should be_can_be_revoked
    info.should be_tokens_valid
    info.should be_authorized
    info.should be_renewable

    AuthProto::State::Session.instance_methods(false).grep(/\?\z/).each do |predicate|
      info.public_send(predicate).should == session.public_send(predicate)
    end
  end

  it "should follow a pending session through authorization without exposing internal authorization secrets" do
    info = described_class.new(session)

    info.should be_pending
    info.should_not be_authorized
    info.should_not be_tokens_valid
    info.should_not be_renewable
    info.should_not be_has_limited_scope
    info.access_token.should be_nil
    info.refresh_token.should be_nil
    info.expires_in.should be_nil
    info.expires_at.should be_nil
    info.granted_scope.should be_nil
    info.did.should be_nil
    info.should_not respond_to(:dpop_key)
    info.should_not respond_to(:pkce_verifier)
    info.should_not respond_to(:state_token)

    session.tokens = tokens
    info.should_not be_pending
    info.access_token.should == 'access'
    info.did.should == 'did:plc:alice'
    info.should be_authorized
  end

  it "should read replacement tokens and updated server metadata from the same session" do
    session.tokens = tokens
    info = described_class.new(session)
    session.tokens = AuthProto::State::TokenSet.new(
      access_token: 'replacement', token_type: 'DPoP', expires_in: 7200,
      scope: session.requested_scope, sub: tokens.sub
    )
    server.stubs(:revocation_endpoint).returns(nil)

    info.access_token.should == 'replacement'
    info.refresh_token.should be_nil
    info.expires_in.should == 7200
    info.expires_at.should == now + 7200
    info.granted_scope.should == session.requested_scope
    info.should_not be_has_limited_scope
    info.should_not be_renewable
    info.should_not be_can_be_revoked
    info.to_h[:access_token].should == 'replacement'
  end

  it "should recalculate remaining lifetime and validity as time passes" do
    session.tokens = tokens
    info = described_class.new(session)
    Time.stubs(:now).returns(now + 60)
    info.expires_in.should == 3540
    info.should be_tokens_valid

    Time.stubs(:now).returns(now + 3570)
    info.expires_in.should == 30
    info.should_not be_authorized

    Time.stubs(:now).returns(now + 4000)
    info.expires_in.should == -400
    info.expires_at.should == now + 3600
    info.should_not be_tokens_valid
    info.should_not be_authorized
  end

  it "should read current strings directly from the session and its tokens" do
    session.tokens = tokens
    info = described_class.new(session)
    tokens.access_token.replace('mutated-access')
    tokens.refresh_token.replace('mutated-refresh')
    tokens.scope.replace('atproto repo:app.bsky.feed.post')
    tokens.sub.replace('did:plc:changed')

    info.access_token.should == 'mutated-access'
    info.refresh_token.should == 'mutated-refresh'
    info.granted_scope.should == 'atproto repo:app.bsky.feed.post'
    info.did.should == 'did:plc:changed'
    info.session_id.should equal(session.session_id)
    info.requested_scope.should equal(session.requested_scope)
    info.pds.should equal(session.pds)
  end

  it "should read current values into a separate hash without exposing session setters" do
    session.tokens = tokens
    info = described_class.new(session)
    hash = info.to_h
    hash[:access_token] = 'different'

    info.access_token.should == 'access'
    info.should_not respond_to(:access_token=)
    info.should_not respond_to(:tokens=)
  end
  describe "granted scopes" do
    let(:scope) { 'atproto transition:email' }
    let(:did) { 'did:plc:alice' }
    let(:session) { AuthProto::State::Session.new(client_id: 'http://localhost', scope: scope) }
    let(:info) { described_class.new(session) }
    let(:tokens) do
      AuthProto::State::TokenSet.new(
        access_token: 'access', token_type: 'DPoP', expires_in: 3600, scope: scope, sub: did
      )
    end

    it "should report no grant and no limitation before authorization" do
      info.granted_scope.should be_nil
      info.has_limited_scope?.should be false
    end

    {
      'atproto' => true,
      'transition:email atproto' => false,
      'atproto transition:email transition:email' => false,
      'atproto repo:app.bsky.feed.post' => true
    }.each do |granted, limited|
      it "should compare requested scope tokens with the grant #{granted}" do
        session.tokens = AuthProto::State::TokenSet.new(
          access_token: 'access', token_type: 'DPoP', expires_in: 3600, scope: granted, sub: did
        )

        session.requested_scope.should == scope
        info.granted_scope.should == granted
        info.has_limited_scope?.should == limited
        session.session_data.granted_scope.should == granted
      end
    end

    it "should expose a changed grant after replacement tokens are assigned" do
      session.tokens = tokens
      info.has_limited_scope?.should be false

      session.tokens = AuthProto::State::TokenSet.new(
        access_token: 'replacement', token_type: 'DPoP', expires_in: 3600, scope: 'atproto', sub: did
      )

      info.granted_scope.should == 'atproto'
      info.has_limited_scope?.should be true
      session.requested_scope.should == scope
    end
  end
end
