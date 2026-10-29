# frozen_string_literal: true

require 'authproto/serialization/stored_nonce'

describe AuthProto::Serialization::StoredNonce do
  let(:stored_nonce) do
    AuthProto::DPoP::StoredNonce.new(
      "test_nonce",
      "https://example.com"
    )
  end
  let(:serializer) { AuthProto::Serialization::StoredNonce.new }

  it "should roundtrip a stored nonce object" do
    serialized = serializer.serialize(stored_nonce)
    deserialized = serializer.deserialize(serialized)

    deserialized.value.should == stored_nonce.value
    deserialized.server_url.should == stored_nonce.server_url
    deserialized.timestamp.to_i.should == stored_nonce.timestamp.to_i
  end

  it "should validate object type" do
    expect {
      serializer.serialize(Object.new)
    }.to raise_error(AuthProto::Serialization::ValidationError)
  end
end
