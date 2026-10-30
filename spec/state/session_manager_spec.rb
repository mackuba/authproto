# frozen_string_literal: true

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
  let(:session_manager) { AuthProto::State::SessionManager.new }
  let(:storage) { AuthProto::Storage::Memory.new }

  before do
    AuthProto.stubs(:storage).returns(storage)
  end

  describe "#create_session" do
    it "should create and store a new session" do
      session = session_manager.create_session(client_id: client_id, scope: scope, auth_server: auth_server, did: did)

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
      retrieved = session_manager.get_session_by_state(updated.state_token)

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

    it "should update both session and state mapping atomically" do
      original_state = session.state_token

      # Verify both session and state mapping are updated
      updates = []
      storage.define_singleton_method(:set) do |key, value|
        updates << key
        super(key, value)
      end

      session_manager.update_session(session)

      session_key = AuthProto::Storage::KeyBuilder.session_key(session.session_id)
      state_key = AuthProto::Storage::KeyBuilder.state_key(original_state)

      updates.should include(session_key)
      updates.should include(state_key)
    end
  end

  describe "#get_session" do
    it "should retrieve an existing session by ID" do
      original = session_manager.create_session(client_id: client_id, scope: scope, auth_server: auth_server, did: did)
      retrieved = session_manager.get_session(original.session_id)

      retrieved.session_id.should == original.session_id
      retrieved.client_id.should == original.client_id
      retrieved.scope.should == original.scope
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

  describe "#get_session_by_state" do
    it "should retrieve a session by a valid state token" do
      original = session_manager.create_session(client_id: client_id, scope: scope, auth_server: auth_server, did: did)
      retrieved = session_manager.get_session_by_state(original.state_token)
      retrieved.session_id.should == original.session_id
    end

    it "should return nil for an invalid state token" do
      session_manager.create_session(client_id: client_id, scope: scope)
      session_manager.get_session_by_state("invalid_state_token").should be_nil
    end

    it "should return nil for nil state" do
      session_manager.get_session_by_state(nil).should be_nil
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
      session_manager.get_session_by_state("any_state").should be_nil
    end
  end
end
