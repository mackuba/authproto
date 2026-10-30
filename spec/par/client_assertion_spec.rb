# frozen_string_literal: true

describe AuthProto::PAR::ClientAssertion do
  let(:client_id) { "test-client-id" }
  let(:audience) { "https://example.com/oauth/token" }
  let(:signing_key) do
    base_key = JOSE::JWK.generate_key([:ec, "P-256"])
    base_map = base_key.to_map

    key_map = {
      "kty" => base_map["kty"],
      "crv" => base_map["crv"],
      "x" => base_map["x"],
      "y" => base_map["y"],
      "d" => base_map["d"],
      "use" => "sig",
      "kid" => "test-key-id"
    }

    JOSE::JWK.from_map(key_map)
  end
  let(:client_assertion) { AuthProto::PAR::ClientAssertion.new(client_id: client_id, signing_key: signing_key) }

  describe "#generate_jwt" do
    it "should generate a valid JWT assertion" do
      lifetime = 300
      now = Time.now.to_i
      Time.stubs(:now).returns(Time.at(now)) # Stub Time.now for predictable timestamps

      jwt = client_assertion.generate_jwt(audience: audience, lifetime: lifetime)
      public_key = JWT::JWK.import(signing_key.to_public.to_map.to_h).public_key
      decoded, header = JWT.decode(jwt, public_key, true, { algorithm: "ES256" })

      # Verify claims
      decoded["iss"].should == client_id
      decoded["sub"].should == client_id
      decoded["aud"].should == audience
      decoded["jti"].should_not be_nil
      decoded["iat"].should == now
      decoded["exp"].should == now + lifetime

      # Verify header
      header["alg"].should == "ES256"
      header["typ"].should == "JWT"
      header["kid"].should == "test-key-id"
    end

    it "should raise an error if signing fails" do
      client_assertion
      client_assertion.signing_key.stubs(:to_map).raises(ArgumentError, "Invalid key")

      expect {
        client_assertion.generate_jwt(audience: audience)
      }.to raise_error(AuthProto::PAR::ClientAssertion::Error) { |error|
        error.message.should match(/Failed to generate client assertion/)
      }
    end

    it "should wrap JWT signing errors when only a public key is supplied" do
      expect {
        AuthProto::PAR::ClientAssertion.new(client_id: client_id, signing_key: signing_key.to_public)
      }.to raise_error(AuthProto::PAR::ClientAssertion::Error, /signing_key must be a private key/)
    end

    it "should reject a signing key whose curve does not match ES256" do
      expect {
        AuthProto::PAR::ClientAssertion.new(client_id: client_id, signing_key: JOSE::JWK.generate_key([:ec, "P-384"]))
      }.to raise_error(AuthProto::PAR::ClientAssertion::Error, /EC P-256/)
    end

    it "should reject a JWK algorithm that conflicts with ES256" do
      key = JOSE::JWK.from_map(signing_key.to_map.to_h.merge("alg" => "ES384"))
      expect {
        AuthProto::PAR::ClientAssertion.new(client_id: client_id, signing_key: key)
      }.to raise_error(AuthProto::PAR::ClientAssertion::Error, /permit ES256 signing/)
    end

    it "should default the lifetime to 5 minutes" do
      now = Time.now.to_i
      Time.stubs(:now).returns(Time.at(now))

      jwt = client_assertion.generate_jwt(audience: audience)
      public_key = JWT::JWK.import(signing_key.to_public.to_map.to_h).public_key
      decoded, header = JWT.decode(jwt, public_key, true, { algorithm: "ES256" })

      decoded["exp"].should == now + 300 # Default lifetime of 300 seconds
    end

    it "should set a unique jti for each assertion" do
      jti_values = []
      5.times do
        jwt = client_assertion.generate_jwt(audience: audience)
        public_key = JWT::JWK.import(signing_key.to_public.to_map.to_h).public_key
        decoded, = JWT.decode(jwt, public_key, true, { algorithm: "ES256" })
        jti_values << decoded["jti"]
      end

      jti_values.uniq.size.should == 5 # All jti values must be unique
    end

    it "should include the correct kid in the header" do
      jwt = client_assertion.generate_jwt(audience: audience)
      public_key = JWT::JWK.import(signing_key.to_public.to_map.to_h).public_key
      decoded, header = JWT.decode(jwt, public_key, true, { algorithm: "ES256" })

      header["kid"].should == "test-key-id"
    end
  end
end
