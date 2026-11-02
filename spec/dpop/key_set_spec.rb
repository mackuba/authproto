# frozen_string_literal: true

require 'json'

describe AuthProto::DPoP::KeySet do
  let(:valid_keypair) { JOSE::JWK.generate_key([:ec, "P-256"]) }
  let(:invalid_keypair) { JOSE::JWK.generate_key([:rsa, 2048]) }

  describe "#initialize" do
    it "should create a KeySet with a valid EC keypair" do
      keyset = AuthProto::DPoP::KeySet.new(valid_keypair)
      keyset.key.should == valid_keypair
    end

    it "should raise an error when initialized with an invalid keypair" do
      expect {
        AuthProto::DPoP::KeySet.new(invalid_keypair)
      }.to raise_error(AuthProto::DPoP::KeySet::KeyError)
    end

    it "should generate a new keypair if none is provided" do
      keyset = AuthProto::DPoP::KeySet.new
      key = keyset.key
      key.to_map["kty"].should == "EC"
      key.to_map["crv"].should == "P-256"
    end
  end

  describe "key validation" do
    it "should reject a public key without private signing material" do
      expect {
        described_class.new(valid_keypair.to_public)
      }.to raise_error(described_class::KeyError)
    end

    it "should reject a key when its signing self-test fails verification" do
      valid_keypair.stubs(:verify).returns([false, nil, nil])

      expect {
        described_class.new(valid_keypair)
      }.to raise_error(described_class::KeyError, /signature verification error/)
    end
  end

  describe "#public_jwk" do
    it "should return the public key in JWK format" do
      keyset = AuthProto::DPoP::KeySet.new(valid_keypair)

      public_jwk = keyset.public_jwk
      public_jwk["kty"].should == "EC"
      public_jwk["crv"].should == "P-256"
      public_jwk.should be_a(Hash)
      public_jwk.keys.sort.should == %w[crv kty x y]
      public_jwk.should == valid_keypair.to_public_map.to_h
    end
  end

  describe "#sign_segments" do
    it "should sign a JSON payload with ES256 even when a different algorithm is requested" do
      keyset = AuthProto::DPoP::KeySet.new(valid_keypair)
      signature = keyset.sign_segments({ alg: 'ES384', typ: 'dpop+jwt' }, { nested: { value: 'test' } })
      verified, payload, header = valid_keypair.verify(signature)

      verified.should be_truthy
      JSON.parse(payload)['nested']['value'].should == 'test'
      header.to_map['alg'].should == 'ES256'
    end
  end

  describe "#to_jwk" do
    it "should export the keypair in JWK format including private key" do
      keyset = AuthProto::DPoP::KeySet.new(valid_keypair)
      jwk = keyset.to_jwk(include_private: true)
      jwk["kty"].should == "EC"
      jwk["crv"].should == "P-256"
      (jwk.key?("d")).should be_truthy
    end

    it "should export the public key only when include_private is false" do
      keyset = AuthProto::DPoP::KeySet.new(valid_keypair)
      jwk = keyset.to_jwk(include_private: false)
      jwk["kty"].should == "EC"
      jwk["crv"].should == "P-256"
      (jwk.key?("d")).should be_falsey
    end
  end

  describe ".from_jwk" do
    it "should create a KeySet instance from a JWK" do
      keyset = AuthProto::DPoP::KeySet.from_jwk(valid_keypair.to_map)
      keyset.should be_an_instance_of(AuthProto::DPoP::KeySet)
    end

    it "should raise an error if importing the JWK fails" do
      invalid_jwk = { "kty" => "RSA", "n" => "mocked_n", "e" => "mocked_e" }
      expect {
        AuthProto::DPoP::KeySet.from_jwk(invalid_jwk)
      }.to raise_error(AuthProto::DPoP::KeySet::KeyError)
    end
  end
end
