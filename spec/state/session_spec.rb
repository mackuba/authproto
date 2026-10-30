# frozen_string_literal: true

describe AuthProto::State::Session do
  let(:client_id) { "test_client_id" }
  let(:scope) { "read write" }
  let(:auth_server) { nil }
  let(:did) { "did:example:1234" }
  let(:tokens) do
    AuthProto::State::TokenSet.new(
      access_token: "valid_access_token",
      token_type: "DPoP",
      expires_in: 3600,
      refresh_token: "valid_refresh_token",
      scope: scope,
      sub: did
    )
  end
  let(:session) do
    AuthProto::State::Session.new(client_id: client_id, scope: scope, auth_server: auth_server, did: did)
  end

  describe "#initialize" do
    let(:auth_server) { mock("AuthorizationServer") }

    it "should initialize with valid parameters" do
      session.session_id.should_not be_nil
      session.state_token.should_not be_nil
      session.client_id.should == client_id
      session.scope.should == scope
      session.auth_server.should == auth_server
      session.did.should == did
      session.pkce_verifier.should_not be_nil
      session.pkce_challenge.should_not be_nil
      session.tokens.should be_nil
    end

    it "should generate unique session_id and state_token" do
      another_session = AuthProto::State::Session.new(client_id: client_id, scope: scope)
      session.session_id.should_not == another_session.session_id
      session.state_token.should_not == another_session.state_token
    end
  end

  describe "#authorization_server=" do
    it "should set the authorization server if not already set" do
      new_server = mock("AuthorizationServer")
      session.authorization_server = new_server
      session.auth_server.should == new_server
    end

    describe "when an existing authorization server is set" do
      let(:auth_server) { mock("AuthorizationServer", issuer: "https://auth.example.com") }

      it "should raise an error if setting a different authorization server" do
        new_server = mock("AuthorizationServer", issuer: "https://auth2.example.com")
        expect {
          session.authorization_server = new_server
        }.to raise_error(AuthProto::State::SessionError)
      end
    end
  end

  describe "#did=" do
    describe "when the DID is not already has a DID" do
      let(:did) { nil }

      it "should set the DID" do
        new_did = "did:example:5678"
        session.did = new_did
        session.did.should == new_did
      end
    end

    it "should raise an error if setting a different DID" do
      new_did = "did:example:5678"
      expect {
        session.did = new_did
      }.to raise_error(AuthProto::State::SessionError)
    end
  end

  describe "#tokens=" do
    it "should set the tokens if they match the session DID" do
      session.tokens = tokens
      session.tokens.should == tokens
    end

    it "should set the DID if it was not previously set" do
      session_without_did = AuthProto::State::Session.new(client_id: client_id, scope: scope)
      session_without_did.tokens = tokens
      session_without_did.did.should == tokens.sub
    end

    it "should raise an error if the tokens' subject does not match the session DID" do
      mismatched_tokens = AuthProto::State::TokenSet.new(
        access_token: "valid_access_token",
        token_type: "DPoP",
        expires_in: 3600,
        scope: scope,
        sub: "did:example:5678"
      )
      expect {
        session.tokens = mismatched_tokens
      }.to raise_error(AuthProto::State::SessionError)
    end
  end

  describe "#authorized?" do
    it "should return true if tokens are set and not expired" do
      session.tokens = tokens
      session.authorized?.should be true
    end

    it "should return false if tokens are nil" do
      session.authorized?.should be false
    end

    it "should return false if tokens are expired" do
      expired_tokens = AuthProto::State::TokenSet.new(
        access_token: "expired_access_token",
        token_type: "DPoP",
        expires_in: 1,
        scope: scope,
        sub: did
      )
      expired_tokens.instance_variable_set(:@expires_at, Time.now - 10)
      session.tokens = expired_tokens
      session.authorized?.should be false
    end
  end

  describe "#renewable?" do
    it "should return true if tokens are set and renewable" do
      session.tokens = tokens
      session.renewable?.should be true
    end

    it "should return false if tokens are nil" do
      session.renewable?.should be false
    end

    it "should return false if tokens are not renewable" do
      non_renewable_tokens = AuthProto::State::TokenSet.new(
        access_token: "valid_access_token",
        token_type: "DPoP",
        expires_in: 3600,
        scope: scope,
        sub: did
      )
      session.tokens = non_renewable_tokens
      session.renewable?.should be false
    end
  end
end
