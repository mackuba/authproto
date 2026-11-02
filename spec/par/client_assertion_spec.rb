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

  describe "signing key operations" do
    [nil, 'sign', [], ['verify'], ['sign', 'sign'], ['sign', 'verify', 'verify'],
     ['sign', 'decrypt'], ['sign', 'encrypt'], ['sign', 'wrapKey'], ['sign', 'deriveKey'],
     ['sign', 'unknown'], ['SIGN'], ['sign', 123]].each do |operations|
      [nil, 'sig'].each do |use|
        it "should reject key_ops #{operations.inspect} with use #{use.inspect}" do
          key = signing_key.to_map.to_h.except('use').merge('key_ops' => operations)
          key['use'] = use if use

          expect {
            described_class.new(client_id: client_id, signing_key: key)
          }.to raise_error(described_class::Error, /key_ops/)
        end
      end
    end

    [nil, ['sign'], ['sign', 'verify'], ['verify', 'sign']].each do |operations|
      [nil, 'sig'].each do |use|
        it "should accept signing key_ops #{operations.inspect} with use #{use.inspect}" do
          key = signing_key.to_map.to_h.except('use')
          key['key_ops'] = operations unless operations.nil?
          key['use'] = use if use
          signer = described_class.new(client_id: client_id, signing_key: key)
          token = signer.generate_jwt(audience: audience)
          public_key = JWT::JWK.import(signing_key.to_public_map.to_h).public_key

          JWT.decode(token, public_key, true, algorithms: ['ES256']).first['iss'].should == client_id
        end
      end
    end
  end

  describe "#generate_jwt" do
    it "should reuse the imported key while generating fresh claims for each request" do
      signer = client_assertion
      JWT::JWK.expects(:import).never
      now = Time.now.to_i
      Time.stubs(:now).returns(Time.at(now))
      first = JWT.decode(signer.generate_jwt(audience: audience), nil, false).first
      Time.stubs(:now).returns(Time.at(now + 10))
      second = JWT.decode(signer.generate_jwt(audience: 'https://other.example.com'), nil, false).first

      second['jti'].should_not == first['jti']
      second['iat'].should == now + 10
      second['exp'].should == now + 310
      second['aud'].should == 'https://other.example.com'
    end

    it "should generate a valid JWT assertion" do
      lifetime = 300
      now = Time.now.to_i
      Time.stubs(:now).returns(Time.at(now)) # Stub Time.now for predictable timestamps

      jwt = client_assertion.generate_jwt(audience: audience, lifetime: lifetime)
      public_key = JWT::JWK.import(signing_key.to_public_map.to_h).public_key
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
      JWT.stubs(:encode).raises(ArgumentError, "Invalid key")

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
      public_key = JWT::JWK.import(signing_key.to_public_map.to_h).public_key
      decoded, header = JWT.decode(jwt, public_key, true, { algorithm: "ES256" })

      decoded["exp"].should == now + 300 # Default lifetime of 300 seconds
    end

    it "should set a unique jti for each assertion" do
      jti_values = []
      5.times do
        jwt = client_assertion.generate_jwt(audience: audience)
        public_key = JWT::JWK.import(signing_key.to_public_map.to_h).public_key
        decoded, = JWT.decode(jwt, public_key, true, { algorithm: "ES256" })
        jti_values << decoded["jti"]
      end

      jti_values.uniq.size.should == 5 # All jti values must be unique
    end

    it "should include the correct kid in the header" do
      jwt = client_assertion.generate_jwt(audience: audience)
      public_key = JWT::JWK.import(signing_key.to_public_map.to_h).public_key
      decoded, header = JWT.decode(jwt, public_key, true, { algorithm: "ES256" })

      header["kid"].should == "test-key-id"
    end
  end
end
