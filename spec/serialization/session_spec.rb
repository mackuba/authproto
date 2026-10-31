# frozen_string_literal: true

require 'json'

describe AuthProto::Serialization::Session do
  let(:client_id) { "test_client" }
  let(:scope) { "test_scope" }
  let(:session) do
    AuthProto::State::Session.new(
      client_id: client_id,
      scope: scope
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
    deserialized.pkce_verifier.should == session.pkce_verifier
    deserialized.pkce_challenge.should == session.pkce_challenge
  end

  it "should encrypt sensitive session data" do
    serialized = JSON.parse(serializer.serialize(session))

    serialized.dig("data", "pkce_verifier").should be_encrypted
    serialized.dig("data", "tokens", "access_token").should be_encrypted if session.tokens
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
