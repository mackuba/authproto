# frozen_string_literal: true

require_relative '../configuration'
require_relative '../serialization/session'
require_relative '../storage/key_builder'
require_relative 'session'

module AuthProto
  module State

    #
    # Manages active OAuth sessions with secure persistent storage
    #

    class SessionManager

      # Creates a session manager and its encrypted session serializer.
      # @raise [ArgumentError] if `ATPROTO_MASTER_KEY` is not valid Base64
      #
      def initialize
        @serializer = Serialization::Session.new
      end

      # Creates and stores a session and its state-token lookup under a storage lock.
      #
      # @param client_id [String] OAuth client ID
      # @param scope [String] requested space-separated scopes
      # @param auth_server [Metadata::AuthorizationServer, nil] pre-resolved authorization server
      # @param did [String, nil] pre-resolved account DID
      #
      # @return [Session] newly created session
      # @raise [PKCE::Error] if session PKCE generation fails
      # @raise [Storage::StorageError] if writing or locking fails
      # @raise [Serialization::ValidationError] if the session cannot be serialized
      # @raise [Encryption::EncryptionError] if sensitive fields cannot be encrypted
      #
      def create_session(client_id:, scope:, auth_server: nil, did: nil)
        session = Session.new(
          client_id: client_id,
          scope: scope,
          auth_server: auth_server,
          did: did
        )

        # Store both session and state mapping atomically
        session_key = Storage::KeyBuilder.session_key(session.session_id)
        state_key = Storage::KeyBuilder.state_key(session.state_token)

        AuthProto.storage.with_lock(session_key, ttl: 30) do
          serialized = @serializer.serialize(session)
          AuthProto.storage.set(session_key, serialized)
          AuthProto.storage.set(state_key, session.session_id)
        end

        session
      end

      # Persists a session under a storage lock.
      #
      # @param session [Session] session to persist
      # @return [Session] the supplied session
      # @raise [Storage::StorageError] if writing or locking fails
      # @raise [Serialization::ValidationError] if the session cannot be serialized
      # @raise [Encryption::EncryptionError] if sensitive fields cannot be encrypted
      #
      def update_session(session)
        session_key = Storage::KeyBuilder.session_key(session.session_id)

        AuthProto.storage.with_lock(session_key, ttl: 30) do
          serialized = @serializer.serialize(session)
          AuthProto.storage.set(session_key, serialized)
        end

        session
      end

      # Persists successful authorization without its state token and removes the callback lookup.
      #
      # @param session [Session] session with successfully validated and assigned tokens
      # @return [Session] the supplied session, with its state token cleared
      # @raise [Storage::StorageError] if writing, deletion or locking fails
      # @raise [Serialization::ValidationError] if the session cannot be serialized
      # @raise [Encryption::EncryptionError] if sensitive fields cannot be encrypted
      #
      def complete_authorization(session)
        state_token = session.state_token
        session.clear_state_token
        update_session(session)

        AuthProto.storage.delete(Storage::KeyBuilder.state_key(state_token)) if state_token

        session
      end

      # Loads and decrypts a session by ID.
      #
      # Returns `nil` for missing, unreadable or malformed sessions and for expired
      # sessions that have no refresh token. Read/deserialization errors are logged.
      #
      # @param session_id [String] session identifier
      # @return [Session, nil] restored session, or `nil` if unavailable
      #
      def get_session(session_id)
        session_key = Storage::KeyBuilder.session_key(session_id)

        begin
          serialized = AuthProto.storage.get(session_key)
          return nil unless serialized
        rescue StandardError => e
          AuthProto.configuration.logger.error("Failed to get session: #{e.message}")
          return nil
        end

        begin
          session = @serializer.deserialize(serialized)
          return nil if !session.renewable? && session.tokens&.expired?

          session
        rescue StandardError => e
          AuthProto.configuration.logger.error("Failed to deserialize session: #{e.message}")
          nil
        end
      end

      # Finds a stored session using its OAuth callback state token.
      #
      # Storage read errors are logged and treated as a missing session.
      #
      # @param state [String, nil] callback state token
      # @return [Session, nil] restored session, or `nil` if unavailable
      #
      def get_session_by_state_token(state_token)
        return nil unless state_token

        state_key = Storage::KeyBuilder.state_key(state_token)

        begin
          session_id = AuthProto.storage.get(state_key)
          return nil unless session_id
        rescue StandardError => e
          AuthProto.configuration.logger.error("Failed to get session by state: #{e.message}")
          return nil
        end

        session = get_session(session_id)

        session if !session.nil? && session.state_token == state_token
      end

      # Deletes a session and its state mapping if it can be retrieved.
      #
      # @param session_id [String] session identifier
      # @return [void]
      # @raise [Storage::StorageError] if deletion or locking fails
      #
      def delete_session(session_id)
        session = get_session(session_id)
        return unless session

        session_key = Storage::KeyBuilder.session_key(session_id)
        AuthProto.storage.with_lock(session_key, ttl: 30) do
          AuthProto.storage.delete(session_key)
          AuthProto.storage.delete(Storage::KeyBuilder.state_key(session.state_token)) if session.state_token
        end
      end

      # Provides an expiry cleanup hook; currently performs no work.
      # Expiry is handled through backend TTLs and retrieval validation.
      #
      # @return [void]
      #
      def cleanup_expired
        # No-op - expiry handled by storage TTL and retrieval validation
      end
    end
  end
end
