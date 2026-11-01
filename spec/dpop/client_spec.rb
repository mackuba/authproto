# frozen_string_literal: true

require 'json'

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
  let(:response) { { status: 200, headers: response_headers, body: '{}' } }

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
        proof = client.generate_proof(session: current, method: method, uri: uri)
        current.dpop_key.key.verify(proof).first.should be_truthy
        different = current.equal?(session) ? other : session
        different.dpop_key.key.verify(proof).first.should be_falsey
        client.proof_generator.should equal(generator)
        client.nonce_manager.should equal(nonces)
      end
    end

    it "should use each session's nonce through interleaved response processing and proof generation" do
      other = AuthProto::State::Session.new(client_id: 'client', scope: 'atproto')
      client.process_response(
        response.merge(headers: { 'DPoP-Nonce' => 'first' }), server_url: uri, session_id: session.session_id
      )
      client.process_response(
        response.merge(headers: { 'DPoP-Nonce' => 'second' }), server_url: uri, session_id: other.session_id
      )
      client.process_response(
        response.merge(headers: { 'DPoP-Nonce' => 'updated-first' }), server_url: uri, session_id: session.session_id
      )

      [[session, 'updated-first'], [other, 'second'], [session, 'updated-first']].each do |current, expected_nonce|
        proof = client.generate_proof(session: current, method: method, uri: uri)
        verified, payload, = current.dpop_key.key.verify(proof)
        verified.should be_truthy
        JSON.parse(payload)['nonce'].should == expected_nonce
      end
    end

    it "should generate a DPoP proof using proof_generator" do
      client.nonce_manager.expects(:get)
            .with(server_url: "https://example.com", session_id: session.session_id).returns(nonce)
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
      client.nonce_manager.expects(:get)
            .with(server_url: "https://example.com", session_id: session.session_id).returns(nil)
      client.proof_generator.expects(:generate).raises(StandardError, "Generation failed")

      expect {
        client.generate_proof(session: session, method: method, uri: uri)
      }.to raise_error(AuthProto::DPoP::Client::Error)
    end
  end

  describe "#has_nonce_error?" do
    it "should recognize a 400 JSON nonce error" do
      client.has_nonce_error?(response.merge(status: 400, body: '{"error":"use_dpop_nonce"}')).should be true
    end

    [nil, '', 'broken', 'null', '[]', 'true', '42', '"text"', '{}', '{"error":"invalid_grant"}'].each do |body|
      it "should ignore a 400 body that is not a nonce error: #{body.inspect}" do
        client.has_nonce_error?(response.merge(status: 400, body: body)).should be false
      end
    end

    [
      'DPoP error="use_dpop_nonce"',
      'dPoP ERROR = "use_dpop_nonce", algs="ES256"',
      'DPoP error_description="Expired nonce, please retry", error="use_dpop_nonce"',
      'DPoP error="use_dpop_nonce", error_description="Say \\"hello\\""'
    ].each do |challenge|
      it "should recognize a case-insensitive 401 nonce challenge with parameters: #{challenge}" do
        headers = { 'wWw-AuThEnTiCaTe' => challenge }
        client.has_nonce_error?(response.merge(status: 401, headers: headers)).should be true
      end
    end

    [
      nil, '', 'Bearer error="use_dpop_nonce"', 'DPoP error="invalid_token"',
      'DPoP error_description="use_dpop_nonce"', 'DPoP error="USE_DPOP_NONCE"',
      'DPoP error="use_dpop_nonce", Bearer realm="example"',
      'DPoP error="use_dpop_nonce", error="invalid_token"', 'DPoP error="use_dpop_nonce',
      'DPoP error="invalid_token", error_description="error=use_dpop_nonce"'
    ].each do |challenge|
      it "should ignore other, malformed or ambiguous 401 challenges: #{challenge.inspect}" do
        headers = { 'www-authenticate' => challenge }
        client.has_nonce_error?(response.merge(status: 401, headers: headers)).should be false
      end
    end

    it "should ignore a missing authentication header and other status codes" do
      client.has_nonce_error?(response.merge(status: 401, headers: {})).should be false
      [200, 201, 403, 429, 500].each do |status|
        client.has_nonce_error?(response.merge(status: status, body: '{"error":"use_dpop_nonce"}')).should be false
      end
    end
  end

  describe "#with_nonce_handling" do
    it "should return the original response and store its nonce without retrying" do
      calls = 0
      result = client.with_nonce_handling(session, uri) do
        calls += 1
        response
      end

      result.should equal(response)
      calls.should == 1
      client.nonce_manager.get(server_url: uri, session_id: session.session_id).should == nonce
    end

    [400, 401].each do |status|
      it "should use the challenge nonce in a fresh proof and store the final nonce for HTTP #{status}" do
        headers = { 'DPoP-Nonce' => 'challenge', 'WWW-Authenticate' => 'DPoP error="use_dpop_nonce"' }
        challenge = { status: status, headers: headers, body: '{"error":"use_dpop_nonce"}' }
        responses = [challenge, response]
        proofs = []

        result = client.with_nonce_handling(session, uri) do
          proof = client.generate_proof(session: session, method: method, uri: uri)
          proofs << JSON.parse(session.dpop_key.key.verify(proof)[1])
          responses.shift
        end

        result.should equal(response)
        proofs.length.should == 2
        proofs.first.should_not have_key('nonce')
        proofs.last['nonce'].should == 'challenge'
        proofs.last['jti'].should_not == proofs.first['jti']
        client.nonce_manager.get(server_url: uri, session_id: session.session_id).should == nonce
      end
    end

    it "should return a second challenge without making a third request" do
      calls = 0
      challenges = []
      result = client.with_nonce_handling(session, uri) do
        calls += 1
        challenges << response.merge(status: 400, headers: { 'DPoP-Nonce' => "nonce-#{calls}" },
                                     body: '{"error":"use_dpop_nonce"}')
        challenges.last
      end

      calls.should == 2
      result.should equal(challenges.last)
      client.nonce_manager.get(server_url: uri, session_id: session.session_id).should == 'nonce-2'
    end

    it "should return other errors without retrying" do
      calls = 0
      failure = response.merge(status: 400, body: '{"error":"invalid_grant"}')
      result = client.with_nonce_handling(session, uri) do
        calls += 1
        failure
      end

      result.should equal(failure)
      calls.should == 1
      client.nonce_manager.get(server_url: uri, session_id: session.session_id).should == nonce
    end

    [1, 2].each do |invalid_attempt|
      it "should reject a missing nonce on attempt #{invalid_attempt} without further requests" do
        calls = 0
        expect {
          client.with_nonce_handling(session, uri) do
            calls += 1
            headers = calls == invalid_attempt ? {} : response_headers
            response.merge(status: 400, headers: headers, body: '{"error":"use_dpop_nonce"}')
          end
        }.to raise_error(described_class::Error, /Missing DPoP-Nonce/)
        calls.should == invalid_attempt
      end
    end

    it "should propagate transport exceptions without retrying" do
      calls = 0
      failure = IOError.new("Connection lost")
      expect {
        client.with_nonce_handling(session, uri) do
          calls += 1
          raise failure
        end
      }.to raise_error { |error| error.should equal(failure) }
      calls.should == 1
    end
  end

  describe "#process_response" do
    it "should update the nonce manager with a valid nonce" do
      client.nonce_manager.expects(:update).with(nonce: nonce, server_url: server_url, session_id: session.session_id)

      client.process_response(response, server_url: server_url, session_id: session.session_id)
    end

    it "should reject a response without a nonce" do
      headers = {}
      client.nonce_manager.expects(:update).never

      expect {
        client.process_response(response.merge(headers: headers), server_url: server_url, session_id: session.session_id)
      }.to raise_error(described_class::Error, /Missing DPoP-Nonce/)
    end

    [200, 201, 400, 401, 500].each do |status|
      [nil, ''].each do |value|
        it "should reject a missing or empty nonce on HTTP #{status}: #{value.inspect}" do
          headers = value.nil? ? {} : { 'dpop-nonce' => value }
          expect {
            client.process_response(response.merge(status: status, headers: headers),
                                    server_url: server_url, session_id: session.session_id)
          }.to raise_error(described_class::Error, /Missing DPoP-Nonce/)
        end
      end
    end

    it "should update from a successful response with a differently cased nonce header" do
      client.process_response(response.merge(headers: { 'dPoP-nOnCe' => 'rotated' }),
                              server_url: server_url, session_id: session.session_id)
      client.nonce_manager.get(server_url: server_url, session_id: session.session_id).should == 'rotated'
    end

    it "should raise an error if nonce update fails" do
      client.nonce_manager.expects(:update).raises(StandardError, "Update failed")

      expect {
        client.process_response(response, server_url: server_url, session_id: session.session_id)
      }.to raise_error(AuthProto::DPoP::Client::Error)
    end
  end
end
