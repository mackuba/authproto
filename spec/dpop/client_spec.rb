# frozen_string_literal: true

describe AuthProto::DPoP::Client do
  let(:mock_key_manager) do
    Class.new(AuthProto::DPoP::KeyManager) do
      def initialize; end
      def public_jwk = { kty: "EC", crv: "P-256", x: "test", y: "test" }
      def sign(jwt_payload) = "signed_jwt"
    end.new
  end

  let(:client) do
    AuthProto::DPoP::Client.new(
      key_manager: mock_key_manager,
      nonce_ttl: 400
    )
  end
  let(:method) { 'POST' }
  let(:uri) { "https://example.com/resource" }
  let(:nonce) { "valid_nonce" }
  let(:access_token) { "test_access_token" }
  let(:server_url) { "https://example.com" }
  let(:proof) { "dpop_proof_jwt" }
  let(:response_headers) { { "DPoP-Nonce" => nonce } }

  describe "#initialize" do
    it "should initialize with a custom key_manager and nonce_ttl" do
      client.key_manager.should == mock_key_manager
      client.nonce_manager.instance_variable_get(:@ttl).should == 400
    end
  end

  describe "#generate_proof" do
    it "should generate a DPoP proof using proof_generator" do
      client.nonce_manager.expects(:get).with("https://example.com").returns(nonce)
      client.proof_generator.expects(:generate).with(
        method: method,
        uri: uri,
        nonce: nonce,
        access_token: access_token
      ).returns(proof)

      generated_proof = client.generate_proof(method: method, uri: uri, access_token: access_token)
      generated_proof.should == proof
    end

    it "should raise an error if proof generation fails" do
      client.nonce_manager.expects(:get).with("https://example.com").returns(nil)
      client.proof_generator.expects(:generate).raises(StandardError, "Generation failed")

      expect {
        client.generate_proof(method: method, uri: uri)
      }.to raise_error(AuthProto::DPoP::Client::Error)
    end
  end

  describe "#process_response" do
    it "should update the nonce manager with a valid nonce" do
      client.nonce_manager.expects(:update).with(nonce: nonce, server_url: server_url)

      client.process_response(response_headers, server_url)
    end

    it "should do nothing if the response headers do not include a nonce" do
      headers = {}
      client.nonce_manager.expects(:update).never

      client.process_response(headers, server_url)
    end

    it "should raise an error if nonce update fails" do
      client.nonce_manager.expects(:update).raises(StandardError, "Update failed")

      expect {
        client.process_response(response_headers, server_url)
      }.to raise_error(AuthProto::DPoP::Client::Error)
    end
  end
end
