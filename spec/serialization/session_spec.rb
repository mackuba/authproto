# frozen_string_literal: true

require 'json'

describe AuthProto::Serialization::Session do
  let(:client_id) { "test_client" }
  let(:scope) { "test_scope" }
  let(:session) do
    AuthProto::State::Session.new(
      client_id: client_id,
      scope: scope,
      pds: 'https://pds.example.com'
    )
  end
  let(:serializer) { AuthProto::Serialization::Session.new }

  it "should roundtrip a session object" do
    serialized = serializer.serialize(session)
    deserialized = serializer.deserialize(serialized)

    deserialized.session_id.should == session.session_id
    deserialized.state_token.should == session.state_token
    deserialized.client_id.should == session.client_id
    deserialized.scope.should == session.scope
    deserialized.pds.should == session.pds
    deserialized.pkce_verifier.should == session.pkce_verifier
    deserialized.pkce_challenge.should == session.pkce_challenge
    deserialized.dpop_key.private_jwk.should == session.dpop_key.private_jwk
  end

  it "should encrypt sensitive session data" do
    serialized = JSON.parse(serializer.serialize(session))

    serialized.dig("data", "pkce_verifier").should be_encrypted
    serialized.dig('data', 'dpop_key', 'd').should be_encrypted
    serialized.dig("data", "tokens", "access_token").should be_encrypted if session.tokens
  end

  it "should preserve requested and granted scopes independently when restoring a session" do
    authorized = AuthProto::State::Session.new(client_id: client_id, scope: 'atproto transition:email')
    authorized.tokens = AuthProto::State::TokenSet.new(
      access_token: 'access', token_type: 'DPoP', expires_in: 3600, scope: 'atproto', sub: 'did:plc:alice'
    )

    restored = serializer.deserialize(serializer.serialize(authorized))

    restored.scope.should == 'atproto transition:email'
    restored.granted_scope.should == 'atproto'
    restored.has_limited_scope?.should be true
  end

  it "should reject sessions without a saved DPoP key instead of generating a replacement" do
    serialized = JSON.parse(serializer.serialize(session))
    serialized.fetch('data').delete('dpop_key')
    AuthProto::DPoP::KeySet.expects(:new).never

    expect {
      serializer.deserialize(JSON.generate(serialized))
    }.to raise_error(AuthProto::Serialization::ValidationError, /missing its private DPoP key/)
  end

  it "should reject a saved public-only DPoP key" do
    serialized = JSON.parse(serializer.serialize(session))
    serialized.fetch('data').fetch('dpop_key').delete('d')

    expect {
      serializer.deserialize(JSON.generate(serialized))
    }.to raise_error(AuthProto::DPoP::KeySet::KeyError)
  end

  it "should preserve the signing key ID without storing the private client-authentication key" do
    bound = AuthProto::State::Session.new(client_id: client_id, scope: scope, signing_key_id: 'client-key',
                                            signing_key_thumbprint: 'thumbprint')
    serialized = serializer.serialize(bound)
    data = JSON.parse(serialized).fetch('data')

    data['signing_key_id'].should == 'client-key'
    data['signing_key_thumbprint'].should == 'thumbprint'
    serializer.deserialize(serialized).signing_key_thumbprint.should == 'thumbprint'
    data.should_not have_key('signing_key')
    data.should_not have_key('d')
    serializer.deserialize(serialized).signing_key_id.should == 'client-key'
  end

  it "should restore older sessions without a signing key ID" do
    serialized = serializer.serialize(session)
    JSON.parse(serialized).fetch('data').should_not have_key('signing_key_id')
    serializer.deserialize(serialized).signing_key_id.should be_nil
  end

  it "should preserve the pending authorization deadline" do
    deadline = Time.at(1_800_000_000.25)
    pending = AuthProto::State::Session.new(
      client_id: client_id, scope: scope, authorization_expires_at: deadline
    )

    serializer.deserialize(serializer.serialize(pending)).authorization_expires_at.should == deadline
  end

  it "should validate object type" do
    expect {
      serializer.serialize(Object.new)
    }.to raise_error(AuthProto::Serialization::ValidationError)
  end
end
