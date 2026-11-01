# frozen_string_literal: true

describe AuthProto::DPoP::Client do
  let(:session) { AuthProto::State::Session.new(client_id: 'client', scope: 'atproto') }
  let(:client) do
    AuthProto::DPoP::Client.new(
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
    it "should initialize with a custom nonce_ttl" do
      client.nonce_manager.instance_variable_get(:@ttl).should == 400
    end
  end

  describe "#generate_proof" do
    it "should reuse shared helpers while signing interleaved sessions with their own keys" do
      other = AuthProto::State::Session.new(client_id: 'client', scope: 'atproto')
      session.dpop_key.public_jwk.should_not == other.dpop_key.public_jwk
      generator = client.proof_generator
      nonces = client.nonce_manager

      [session, other, session].each do |current|
        proof = client.generate_proof(session: current, method: method, uri: uri, nonce: nonce)
        current.dpop_key.key.verify(proof).first.should be_truthy
        different = current.equal?(session) ? other : session
        different.dpop_key.key.verify(proof).first.should be_falsey
        client.proof_generator.should equal(generator)
        client.nonce_manager.should equal(nonces)
      end
    end

    it "should generate a DPoP proof using proof_generator" do
      client.nonce_manager.expects(:get).with("https://example.com").returns(nonce)
      client.proof_generator.expects(:generate).with(
        key_set: session.dpop_key,
        method: method,
        uri: uri,
        nonce: nonce,
        access_token: access_token
      ).returns(proof)

      generated_proof = client.generate_proof(session: session, method: method, uri: uri, access_token: access_token)
      generated_proof.should == proof
    end

    it "should raise an error if proof generation fails" do
      client.nonce_manager.expects(:get).with("https://example.com").returns(nil)
      client.proof_generator.expects(:generate).raises(StandardError, "Generation failed")

      expect {
        client.generate_proof(session: session, method: method, uri: uri)
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
