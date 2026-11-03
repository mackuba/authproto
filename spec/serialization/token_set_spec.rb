# frozen_string_literal: true

require 'json'

describe AuthProto::Serialization::TokenSet do
  let(:token_set) do
    AuthProto::State::TokenSet.new(
      access_token: "test_access_token",
      refresh_token: "test_refresh_token",
      token_type: "DPoP",
      expires_in: 3600,
      scope: "test_scope",
      sub: "test_sub"
    )
  end
  let(:serializer) { AuthProto::Serialization::TokenSet.new }

  it "should roundtrip a token set object" do
    serialized = serializer.serialize(token_set)
    JSON.parse(serialized).fetch('data').should_not have_key('token_type')
    deserialized = serializer.deserialize(serialized)

    deserialized.access_token.should == token_set.access_token
    deserialized.refresh_token.should == token_set.refresh_token
    deserialized.token_type.should == token_set.token_type
    deserialized.scope.should == token_set.scope
    deserialized.sub.should == token_set.sub
  end

  it "should encrypt sensitive token data" do
    serialized = JSON.parse(serializer.serialize(token_set))

    serialized.dig("data", "access_token").should be_encrypted
    serialized.dig("data", "refresh_token").should be_encrypted
  end

  it "should preserve an absent refresh token and an expired access token" do
    tokens = AuthProto::State::TokenSet.new(
      access_token: 'access', token_type: 'DPoP', expires_in: -10, scope: 'atproto', sub: 'did:plc:alice'
    )
    serialized = serializer.serialize(tokens)
    JSON.parse(serialized).fetch('data').should_not have_key('refresh_token')
    restored = serializer.deserialize(serialized)

    restored.refresh_token.should be_nil
    restored.should_not be_renewable
    restored.should be_expired
  end

  it "should validate object type" do
    expect {
      serializer.serialize(Object.new)
    }.to raise_error(AuthProto::Serialization::ValidationError)
  end
end
