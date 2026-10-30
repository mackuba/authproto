# frozen_string_literal: true

require 'base64'
require 'json'
require 'openssl'
require 'securerandom'

UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

describe AuthProto::DPoP::ProofGenerator do
  let(:key_manager) { AuthProto::DPoP::KeyManager.new }
  let(:generator) { AuthProto::DPoP::ProofGenerator.new(key_manager) }
  let(:method) { 'POST' }
  let(:uri) { "https://example.com/path" }

  describe "initialization" do
    it "should require a key manager" do
      expect {
        AuthProto::DPoP::ProofGenerator.new(nil)
      }.to raise_error(AuthProto::DPoP::ProofGenerator::ProofError)
    end

    it "should validate key manager type" do
      expect {
        AuthProto::DPoP::ProofGenerator.new("invalid")
      }.to raise_error(AuthProto::DPoP::ProofGenerator::ProofError)
    end
  end

  describe "#generate" do
    it "should generate valid proof JWT" do
      proof = generator.generate(method: method, uri: uri)
      segments = proof.split(".")
      segments.length.should == 3 # header.payload.signature

      header = JSON.parse(Base64.urlsafe_decode64(segments[0]))
      payload = JSON.parse(Base64.urlsafe_decode64(segments[1]))

      header["typ"].should == "dpop+jwt"
      header["alg"].should == "ES256"
      header["jwk"].should be_a(Hash)

      payload["jti"].should match(UUID_REGEX)
      payload["htm"].should == method
      payload["htu"].should == uri
      payload["iat"].should be_a(Integer)
    end

    it "should include nonce when provided" do
      nonce = SecureRandom.hex
      proof = generator.generate(
        method: method,
        uri: uri,
        nonce: nonce
      )
      payload = extract_payload(proof)
      payload["nonce"].should == nonce
    end

    it "should optionally include access token hash" do
      token = "test_token"
      proof = generator.generate(
        method: method,
        uri: uri,
        access_token: token,
        ath: true
      )
      payload = extract_payload(proof)

      digest = OpenSSL::Digest::SHA256.digest(token)
      expected_hash = Base64.urlsafe_encode64(digest, padding: false)
      payload["ath"].should == expected_hash
    end

    it "should normalize URIs" do
      uri = "https://example.com:443/path?query#fragment"
      proof = generator.generate(method: method, uri: uri)
      payload = extract_payload(proof)
      payload["htu"].should == "https://example.com/path"
    end

    it "should strip query strings while preserving the path and a nondefault port" do
      uri = 'https://example.com:8443/path%2Fsegment?limit=1&cursor=next%2Fpage'
      proof = generator.generate(method: method, uri: uri)

      extract_payload(proof)['htu'].should == 'https://example.com:8443/path%2Fsegment'
    end

    it "should validate http method" do
      expect {
        generator.generate(method: "", uri: uri)
      }.to raise_error(AuthProto::DPoP::ProofGenerator::ProofError)
    end

    it "should validate http uri" do
      expect {
        generator.generate(method: method, uri: "invalid")
      }.to raise_error(AuthProto::DPoP::ProofGenerator::ProofError)
    end

    it "should require https or http uri" do
      expect {
        generator.generate(method: method, uri: "ftp://example.com")
      }.to raise_error(AuthProto::DPoP::ProofGenerator::ProofError)
    end
  end

  private

  def extract_payload(proof)
    payload = proof.split(".")[1]
    JSON.parse(Base64.urlsafe_decode64(payload))
  end
end
