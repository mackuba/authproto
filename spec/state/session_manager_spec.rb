# frozen_string_literal: true

require 'json'

describe AuthProto::State::SessionManager do
  let(:client_id) { "test_client_id" }
  let(:scope) { "read write" }
  let(:auth_server) do
    AuthProto::Metadata::AuthorizationServer.new(
      "issuer" => "https://example.com",
      "token_endpoint" => "https://example.com/token",
      "authorization_endpoint" => "https://example.com/auth",
      "response_types_supported" => ["code"],
      "grant_types_supported" => %w[authorization_code refresh_token],
      "code_challenge_methods_supported" => ["S256"],
      "token_endpoint_auth_methods_supported" => %w[private_key_jwt none],
      "token_endpoint_auth_signing_alg_values_supported" => %w[ES256],
      "scopes_supported" => %w[atproto],
      "dpop_signing_alg_values_supported" => %w[ES256],
      "pushed_authorization_request_endpoint" => "https://example.com/pushed_auth",
      "authorization_response_iss_parameter_supported" => true,
      "require_pushed_authorization_requests" => true,
      "client_id_metadata_document_supported" => true
    )
  end
  let(:did) { "did:example:1234" }
  let(:session_manager) { AuthProto::State::SessionManager.new(client_id: client_id) }
  let(:storage) { AuthProto::Storage::Memory.new }

  before do
    AuthProto.stubs(:storage).returns(storage)
  end

  describe "client ID binding" do
    [nil, '', 123, false].each do |invalid_id|
      it "should reject an invalid manager client ID #{invalid_id.inspect}" do
        expect { described_class.new(client_id: invalid_id) }.to raise_error(ArgumentError, /client_id/)
      end
    end

    it "should retain its client ID independently of the supplied string" do
      configured_id = String.new(client_id)
      manager = described_class.new(client_id: configured_id)
      configured_id.replace('other-client')
      session = manager.create_session(client_id: client_id, scope: scope)

      manager.get_session(session.session_id).client_id.should == client_id
    end

    it "should reject creation for a different client before writing anything" do
      storage.expects(:set).never

      expect {
        session_manager.create_session(client_id: 'other-client', scope: scope)
      }.to raise_error(AuthProto::State::SessionError, /client_id does not match/)
    end

    it "should reject updates and authorization completion without changing a foreign session" do
      owner = described_class.new(client_id: 'other-client')
      session = owner.create_session(client_id: 'other-client', scope: scope)
      state = session.state_token
      key = AuthProto::Storage::KeyBuilder.session_key(session.session_id)
      serialized = storage.get(key)

      expect {
        session_manager.update_session(session)
      }.to raise_error(AuthProto::State::SessionError, /client_id does not match/)
      expect {
        session_manager.complete_authorization(session)
      }.to raise_error(AuthProto::State::SessionError, /client_id does not match/)

      session.state_token.should == state
      storage.get(key).should == serialized
      owner.get_session_by_state_token(state).session_id.should == session.session_id
    end

    it "should reject a foreign client ID even when the signing key binding matches" do
      keys = { 'key' => 'thumbprint' }
      owner = described_class.new(client_id: 'other-client', supported_signing_keys: keys)
      session = owner.create_session(client_id: 'other-client', scope: scope, signing_key_id: 'key')
      reader = described_class.new(client_id: client_id, supported_signing_keys: keys)

      reader.get_session(session.session_id).should be_nil
      reader.get_session_by_state_token(session.state_token).should be_nil
      owner.get_session(session.session_id).should_not be_nil
    end

    it "should reject a stored session without a client ID" do
      session = session_manager.create_session(client_id: client_id, scope: scope)
      key = AuthProto::Storage::KeyBuilder.session_key(session.session_id)
      serialized = JSON.parse(storage.get(key))
      serialized.fetch('data').delete('client_id')
      storage.set(key, JSON.generate(serialized))

      session_manager.get_session(session.session_id).should be_nil
      session_manager.get_session_by_state_token(session.state_token).should be_nil
    end
  end

  describe "#create_session" do
    it "should create and store a new session" do
      session = session_manager.create_session(client_id: client_id, scope: scope,
                                                auth_server: auth_server, did: did)

      # Verify session was stored
      session_key = AuthProto::Storage::KeyBuilder.session_key(session.session_id)
      stored = storage.get(session_key)
      (stored).should be_truthy

      # Verify state mapping was stored
      state_key = AuthProto::Storage::KeyBuilder.state_key(session.state_token)
      state_mapping = storage.get(state_key)
      state_mapping.should == session.session_id
    end
  end

  describe "supported signing keys" do
    let(:key_id) { 'original-key' }
    let(:bound_session) do
      described_class.new(client_id: client_id, supported_signing_keys: { key_id => 'thumbprint' }).create_session(
        client_id: client_id, scope: scope, signing_key_id: key_id
      )
    end

    it "should record the thumbprint from the configured mapping" do
      bound_session.signing_key_thumbprint.should == 'thumbprint'
    end

    it "should reject an unconfigured key ID before storing a session" do
      expect {
        session_manager.create_session(client_id: client_id, scope: scope, signing_key_id: 'unknown')
      }.to raise_error(ArgumentError, /Unsupported signing_key_id/)
    end

    it "should accept sessions made with any supported key" do
      session_id = bound_session.session_id
      reader = described_class.new(
        client_id: client_id, supported_signing_keys: { 'new-key' => 'new-thumbprint', key_id => 'thumbprint' }
      )

      reader.get_session(session_id).signing_key_id.should == key_id
      reader.get_session_by_state_token(bound_session.state_token).session_id.should == session_id
    end

    it "should hide unsupported sessions without deleting their stored data or state lookup" do
      session_id = bound_session.session_id
      reader = described_class.new(client_id: client_id, supported_signing_keys: { 'new-key' => 'new-thumbprint' })

      reader.get_session(session_id).should be_nil
      reader.get_session_by_state_token(bound_session.state_token).should be_nil
      reader.delete_session(session_id)

      storage.exists?(AuthProto::Storage::KeyBuilder.session_key(session_id)).should be_truthy
      storage.exists?(AuthProto::Storage::KeyBuilder.state_key(bound_session.state_token)).should be_truthy
      original_reader = described_class.new(client_id: client_id, supported_signing_keys: { key_id => 'thumbprint' })
      original_reader.get_session(session_id).signing_key_id.should == key_id
    end

    it "should reject a changed thumbprint under the same key ID without deleting the session" do
      reader = described_class.new(client_id: client_id, supported_signing_keys: { key_id => 'different-thumbprint' })
      reader.get_session(bound_session.session_id).should be_nil
      reader.get_session_by_state_token(bound_session.state_token).should be_nil
      matching = described_class.new(client_id: client_id, supported_signing_keys: { key_id => 'thumbprint' })
      matching.get_session(bound_session.session_id).should_not be_nil
    end

    it "should reject a session with a recorded key ID but no thumbprint" do
      stored = bound_session
      key = AuthProto::Storage::KeyBuilder.session_key(stored.session_id)
      serialized = JSON.parse(storage.get(key))
      serialized.fetch('data').delete('signing_key_thumbprint')
      storage.set(key, JSON.generate(serialized))
      reader = described_class.new(client_id: client_id, supported_signing_keys: { key_id => 'thumbprint' })
      reader.get_session(stored.session_id).should be_nil
    end

    it "should reject recorded key IDs when no keys are configured" do
      session_manager.get_session(bound_session.session_id).should be_nil
    end

    it "should only load a session without signing key fields for a public client" do
      session = session_manager.create_session(client_id: client_id, scope: scope)
      reader = described_class.new(client_id: client_id, supported_signing_keys: { 'new-key' => 'new-thumbprint' })

      reader.get_session(session.session_id).should be_nil
      session_manager.get_session(session.session_id).should_not be_nil
    end

    [nil, [], 'key', { '' => 'thumb' }, { 'key' => '' }, { 'key' => 123 }].each do |ids|
      it "should reject invalid supported key IDs #{ids.inspect}" do
        expect {
          described_class.new(client_id: client_id, supported_signing_keys: ids)
        }.to raise_error(ArgumentError, /supported_signing_keys/)
      end
    end
  end

  describe "#update_session" do
    let(:client_id) { "test_client_id" }
    let(:scope) { "read write" }
    let(:session) do
      session_manager.create_session(client_id: client_id, scope: scope)
    end

    it "should update an existing session" do
      # Update session with new data
      session.did = "did:test:123"
      updated = session_manager.update_session(session)

      # Verify session was stored correctly
      retrieved = session_manager.get_session(session.session_id)
      retrieved.did.should == "did:test:123"
      retrieved.session_id.should == session.session_id
      updated.should == session
    end

    it "should maintain state token mapping after update" do
      updated = session_manager.update_session(session)
      retrieved = session_manager.get_session_by_state_token(updated.state_token)

      retrieved.should_not be_nil
      retrieved.session_id.should == session.session_id
    end

    it "should handle storage errors gracefully" do
      failing_storage = Class.new(AuthProto::Storage::Interface) do
        def set(*)
          raise AuthProto::Storage::StorageError, "Storage failure"
        end

        def with_lock(*)
          yield if block_given?
        end
      end.new

      AuthProto.stubs(:storage).returns(failing_storage)

      expect {
        session_manager.update_session(session)
      }.to raise_error(AuthProto::Storage::StorageError)
    end

    it "should leave the existing state mapping untouched when saving session changes" do
      state_key = AuthProto::Storage::KeyBuilder.state_key(session.state_token)
      updates = []
      storage.define_singleton_method(:set) do |key, value, **options|
        updates << key
        super(key, value, **options)
      end

      session.did = did
      session_manager.update_session(session)

      updates.should == [AuthProto::Storage::KeyBuilder.session_key(session.session_id)]
      storage.get(state_key).should == session.session_id
      session_manager.get_session(session.session_id).did.should == did
    end

    it "should not recreate a missing state mapping when saving a pending session" do
      state_key = AuthProto::Storage::KeyBuilder.state_key(session.state_token)
      storage.delete(state_key)
      session_manager.update_session(session)

      storage.exists?(state_key).should be_falsey
    end
  end

  describe "session expiry" do
    let(:now) { Time.utc(2026, 1, 1) }
    let(:session) { session_manager.create_session(client_id: client_id, scope: scope) }
    let(:session_key) { AuthProto::Storage::KeyBuilder.session_key(session.session_id) }
    let(:state_key) { AuthProto::Storage::KeyBuilder.state_key(session.state_token) }

    before do
      Time.stubs(:now).returns(now)
      AuthProto.configuration.stubs(:pending_session_ttl).returns(900)
    end

    def assign_tokens(refresh_token: nil)
      session.tokens = AuthProto::State::TokenSet.new(
        access_token: 'access', refresh_token: refresh_token, token_type: 'DPoP',
        expires_in: 3600, scope: scope, sub: did
      )
    end

    it "should expire both pending records after the default fifteen minutes" do
      session.authorization_expires_at.should == now + 900
      session_id = session.session_id
      original_state_key = state_key

      Time.stubs(:now).returns(now + 899)
      session_manager.get_session(session_id).should_not be_nil
      storage.get(original_state_key).should == session_id

      Time.stubs(:now).returns(now + 900)
      storage.get(session_key).should be_nil
      storage.get(original_state_key).should be_nil
    end

    it "should use the configured lifetime for both pending records" do
      AuthProto.configuration.stubs(:pending_session_ttl).returns(1800)
      session.authorization_expires_at.should == now + 1800
      original_state_key = state_key

      Time.stubs(:now).returns(now + 1800)
      storage.get(session_key).should be_nil
      storage.get(original_state_key).should be_nil
    end

    it "should preserve the pending deadline through loading and updates despite configuration changes" do
      session_id = session.session_id
      original_state_key = state_key
      Time.stubs(:now).returns(now + 600)
      AuthProto.configuration.stubs(:pending_session_ttl).returns(1800)

      restored = session_manager.get_session(session_id)
      restored.authorization_expires_at.should == now + 900
      session_manager.update_session(restored)

      Time.stubs(:now).returns(now + 899)
      session_manager.get_session(session_id).should_not be_nil
      Time.stubs(:now).returns(now + 900)
      storage.get(session_key).should be_nil
      storage.get(original_state_key).should be_nil
    end

    it "should reject expired pending updates without resurrecting the stored session" do
      session_id = session.session_id
      Time.stubs(:now).returns(now + 900)

      expect {
        session_manager.update_session(session)
      }.to raise_error(AuthProto::State::SessionError, "Session has expired")

      session_manager.get_session(session_id).should be_nil
    end

    it "should expire non-refreshable sessions with their access token without extending expiry on updates" do
      assign_tokens
      session_manager.complete_authorization(session)
      Time.stubs(:now).returns(now + 1800)
      restored = session_manager.get_session(session.session_id)
      session_manager.update_session(restored)

      Time.stubs(:now).returns(now + 3500)
      session_manager.get_session(session.session_id).should_not be_nil
      Time.stubs(:now).returns(now + 3600)
      storage.get(session_key).should be_nil
    end

    it "should reject updates of expired non-refreshable sessions" do
      assign_tokens
      Time.stubs(:now).returns(now + 3600)

      expect {
        session_manager.update_session(session)
      }.to raise_error(AuthProto::State::SessionError, "Session has expired")
    end

    it "should clear the pending deadline and storage expiry for renewable sessions" do
      assign_tokens(refresh_token: 'refresh')
      session_manager.complete_authorization(session)
      session.authorization_expires_at.should be_nil

      Time.stubs(:now).returns(now + 7200)
      restored = session_manager.get_session(session.session_id)
      restored.should be_renewable
      restored.authorization_expires_at.should be_nil
      session_manager.update_session(restored)
      storage.get(session_key).should_not be_nil
    end
  end

  describe '#complete_authorization' do
    let(:session) { session_manager.create_session(client_id: client_id, scope: scope) }

    before do
      session.tokens = AuthProto::State::TokenSet.new(
        access_token: 'access', refresh_token: 'refresh', token_type: 'DPoP',
        expires_in: 3600, scope: scope, sub: did
      )
    end

    it "should remove the state token and lookup while retaining the authenticated session" do
      state_token = session.state_token
      session_key = AuthProto::Storage::KeyBuilder.session_key(session.session_id)
      state_key = AuthProto::Storage::KeyBuilder.state_key(state_token)

      session_manager.complete_authorization(session).should equal(session)

      session.state_token.should be_nil
      storage.exists?(state_key).should be_falsey
      JSON.parse(storage.get(session_key)).fetch('data').should_not have_key('state_token')
      session_manager.get_session_by_state_token(state_token).should be_nil
      restored = session_manager.get_session(session.session_id)
      restored.state_token.should be_nil
      restored.tokens.access_token.should == 'access'
      restored.tokens_valid?.should == true
    end

    it "should not recreate a state lookup on later session updates" do
      state_key = AuthProto::Storage::KeyBuilder.state_key(session.state_token)
      session_manager.complete_authorization(session)
      restored = session_manager.get_session(session.session_id)

      session_manager.update_session(restored)

      storage.exists?(state_key).should be_falsey
      storage.exists?(AuthProto::Storage::KeyBuilder.state_key(nil)).should be_falsey
      session_manager.get_session(session.session_id).state_token.should be_nil
    end

    it "should reject a stale lookup if deleting it fails after the session is saved" do
      state_token = session.state_token
      state_key = AuthProto::Storage::KeyBuilder.state_key(state_token)
      storage.expects(:delete).with(state_key).raises(AuthProto::Storage::StorageError, "Deletion failed")

      expect {
        session_manager.complete_authorization(session)
      }.to raise_error(AuthProto::Storage::StorageError)

      storage.get(state_key).should == session.session_id
      session_manager.get_session_by_state_token(state_token).should be_nil
    end

    it "should delete an authenticated session whose state token has already been cleared" do
      session_manager.complete_authorization(session)

      session_manager.delete_session(session.session_id)

      session_manager.get_session(session.session_id).should be_nil
    end
  end

  describe "#get_session" do
    it "should retrieve an existing session by ID" do
      original = session_manager.create_session(client_id: client_id, scope: scope,
                                                auth_server: auth_server, did: did)
      retrieved = session_manager.get_session(original.session_id)

      retrieved.session_id.should == original.session_id
      retrieved.client_id.should == original.client_id
      retrieved.requested_scope.should == original.requested_scope
    end

    it "should return nil for a non-existent session ID" do
      session_manager.get_session("non_existent_session_id").should be_nil
    end

    it "should return nil if deserialization fails" do
      session = session_manager.create_session(client_id: client_id, scope: scope)
      session_key = AuthProto::Storage::KeyBuilder.session_key(session.session_id)

      # Corrupt the stored data
      storage.set(session_key, "invalid json")

      session_manager.get_session(session.session_id).should be_nil
    end

    it "should return nil for expired non-renewable sessions" do
      session = session_manager.create_session(client_id: client_id, scope: scope)

      # Add expired tokens
      tokens = AuthProto::State::TokenSet.new(
        access_token: "expired_token",
        token_type: "DPoP",
        expires_in: 1,
        scope: scope,
        sub: did
      )

      tokens.instance_variable_set(:@expires_at, Time.now - 10)
      session.tokens = tokens

      # Re-store the session with expired tokens
      session_key = AuthProto::Storage::KeyBuilder.session_key(session.session_id)
      serializer = AuthProto::Serialization::Session.new
      storage.set(session_key, serializer.serialize(session))

      # If this still fails, let's inspect what we get back
      result = session_manager.get_session(session.session_id)
      if result
        raise RSpec::Expectations::ExpectationNotMetError, "Expected nil but got session with: expired=#{result.tokens&.expired?}, " \
              "renewable=#{result.renewable?}, refresh_token=#{result.tokens&.refresh_token}"
      end

      session_manager.get_session(session.session_id).should be_nil
    end
  end

  describe "#get_session_by_state_token" do
    it "should retrieve a session by a valid state token" do
      original = session_manager.create_session(client_id: client_id, scope: scope,
                                                auth_server: auth_server, did: did)
      retrieved = session_manager.get_session_by_state_token(original.state_token)
      retrieved.session_id.should == original.session_id
    end

    it "should return nil for an invalid state token" do
      session_manager.create_session(client_id: client_id, scope: scope)
      session_manager.get_session_by_state_token("invalid_state_token").should be_nil
    end

    it "should return nil for nil state" do
      session_manager.get_session_by_state_token(nil).should be_nil
    end
  end

  describe "#delete_session" do
    it "should remove a session and its state mapping" do
      session = session_manager.create_session(client_id: client_id, scope: scope)
      session_key = AuthProto::Storage::KeyBuilder.session_key(session.session_id)
      state_key = AuthProto::Storage::KeyBuilder.state_key(session.state_token)

      session_manager.delete_session(session.session_id)

      (storage.exists?(session_key)).should be_falsey
      (storage.exists?(state_key)).should be_falsey
    end

    it "should handle removal of non-existent session" do
      session_manager.delete_session("non_existent_session_id").should be_nil
    end
  end

  describe "storage integration" do
    it "should handle storage errors gracefully" do
      # Create a failing storage implementation
      failing_storage = Class.new(AuthProto::Storage::Interface) do
        def set(*)
          raise AuthProto::Storage::StorageError, "Storage failure"
        end

        def get(*)
          raise AuthProto::Storage::StorageError, "Storage failure"
        end

        def delete(*)
          raise AuthProto::Storage::StorageError, "Storage failure"
        end

        def exists?(*)
          raise AuthProto::Storage::StorageError, "Storage failure"
        end

        def with_lock(*)
          yield if block_given?
        end
      end.new

      AuthProto.stubs(:storage).returns(failing_storage)

      # Test error handling
      expect {
        session_manager.create_session(client_id: client_id, scope: scope)
      }.to raise_error(AuthProto::Storage::StorageError)

      session_manager.get_session("any_id").should be_nil
      session_manager.get_session_by_state_token("any_state").should be_nil
    end
  end
end
