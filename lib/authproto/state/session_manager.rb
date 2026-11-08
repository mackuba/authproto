# frozen_string_literal: true

require_relative '../configuration'
require_relative '../serialization/session'
require_relative '../storage/key_builder'
require_relative 'session'

module AuthProto
  module State

    #
    # @api private
    #
    # Manages active OAuth sessions with secure persistent storage
    #

    class SessionManager

      # Creates a session manager bound to one client ID and its encrypted session serializer.
      #
      # @param client_id [String] client ID that all managed sessions must match
      # @param supported_signing_keys [Hash{String => String}] key IDs mapped to RFC 7638 SHA-256 thumbprints;
      #   empty for public clients
      # @raise [ArgumentError] if the client ID, key IDs or thumbprints are not nonempty strings
      # @raise [ArgumentError] if `ATPROTO_MASTER_KEY` is not valid Base64
      #
      def initialize(client_id:, supported_signing_keys: {})
        unless client_id.is_a?(String) && !client_id.empty?
          raise ArgumentError, "client_id must be a nonempty string"
        end

        keys = supported_signing_keys

        unless keys.is_a?(Hash) && keys.all? { |id, thumb| [id, thumb].all? { |x| x.is_a?(String) && !x.empty? }}
          raise ArgumentError, "supported_signing_keys must map nonempty key IDs to nonempty thumbprints"
        end

        @client_id = client_id.dup.freeze
        @supported_signing_keys = keys.to_h { |id, thumb| [id.dup.freeze, thumb.dup.freeze] }.freeze
        @serializer = Serialization::Session.new
      end

      # Creates and stores a session and its state-token lookup under a storage lock.
      # The signing key thumbprint is taken from the configured key mapping.
      #
      # @param client_id [String] OAuth client ID
      # @param scope [String] requested space-separated scopes
      # @param auth_server [Metadata::AuthorizationServer, nil] pre-resolved authorization server
      # @param did [String, nil] pre-resolved account DID
      # @param pds [String, nil] PDS URL used for authorization server discovery
      # @param signing_key_id [String, nil] client-authentication key ID selected before PAR
      #
      # @return [Session] newly created session
      # @raise [ArgumentError] if the signing key ID is not configured
      # @raise [SessionError] if the client ID does not match this manager
      # @raise [DPoP::KeySet::KeyError] if session key generation fails
      # @raise [PKCE::Error] if session PKCE generation fails
      # @raise [Storage::StorageError] if writing or locking fails
      # @raise [Serialization::ValidationError] if the session cannot be serialized
      # @raise [Encryption::EncryptionError] if sensitive fields cannot be encrypted
      #
      def create_session(client_id:, scope:, auth_server: nil, did: nil, pds: nil, signing_key_id: nil)
        validate_client_id(client_id)

        if signing_key_id && !@supported_signing_keys.key?(signing_key_id)
          raise ArgumentError, "Unsupported signing_key_id: #{signing_key_id}"
        end

        session = Session.new(
          client_id: client_id,
          scope: scope,
          auth_server: auth_server,
          did: did,
          pds: pds,
          signing_key_id: signing_key_id,
          signing_key_thumbprint: @supported_signing_keys[signing_key_id],
          authorization_expires_at: Time.now + AuthProto.configuration.pending_session_ttl
        )

        # Store the session and state mapping with the same pending authorization lifetime.
        session_key = Storage::KeyBuilder.session_key(session.session_id)
        state_key = Storage::KeyBuilder.state_key(session.state_token)

        AuthProto.storage.with_lock(session_key, ttl: 30) do
          ttl = session_ttl(session)
          serialized = @serializer.serialize(session)
          AuthProto.storage.set(session_key, serialized, ttl: ttl)
          AuthProto.storage.set(state_key, session.session_id, ttl: ttl)
        end

        session
      end

      # Persists a session under a storage lock.
      #
      # Pending sessions retain their original deadline. Non-renewable authenticated sessions
      # expire with their access token; renewable sessions have no storage expiry.
      #
      # @param session [Session] session to persist
      # @return [Session] the supplied session
      # @raise [Storage::StorageError] if writing or locking fails
      # @raise [Serialization::ValidationError] if the session cannot be serialized
      # @raise [Encryption::EncryptionError] if sensitive fields cannot be encrypted
      # @raise [SessionError] if the client ID differs, the pending deadline is missing or the session has expired
      #
      def update_session(session)
        validate_client_id(session.client_id)

        session_key = Storage::KeyBuilder.session_key(session.session_id)

        AuthProto.storage.with_lock(session_key, ttl: 30) do
          ttl = session_ttl(session)
          serialized = @serializer.serialize(session)
          AuthProto.storage.set(session_key, serialized, ttl: ttl)
        end

        session
      end

      # Persists successful authorization without its state token and removes the callback lookup.
      #
      # @param session [Session] session with successfully validated and assigned tokens
      # @return [Session] the supplied session, with its state token cleared
      # @raise [SessionError] if the client ID does not match this manager
      # @raise [Storage::StorageError] if writing, deletion or locking fails
      # @raise [Serialization::ValidationError] if the session cannot be serialized
      # @raise [Encryption::EncryptionError] if sensitive fields cannot be encrypted
      #
      def complete_authorization(session)
        validate_client_id(session.client_id)

        state_token = session.state_token
        session.clear_state_token
        update_session(session)

        AuthProto.storage.delete(Storage::KeyBuilder.state_key(state_token)) if state_token

        session
      end

      # Loads and decrypts a session by ID.
      #
      # Returns `nil` for missing, unreadable or malformed sessions and for expired
      # sessions that have no refresh token. Sessions with an unsupported signing key ID
      # or a missing/mismatching key thumbprint are unavailable but remain in storage.
      # Sessions with a different client ID are unavailable but remain in storage.
      # Public clients require both signing key fields to be absent. Confidential clients require a matching binding.
      # Read/deserialization errors are logged.
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
          return nil unless session.client_id == @client_id

          return nil unless signing_key_matches?(session)

          if session.pending?
            deadline = session.authorization_expires_at
            return nil if !deadline || deadline <= Time.now
          else
            return nil if !session.tokens_valid? && !session.renewable?
          end

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
      # @param state_token [String, nil] callback state token
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


      private

      def signing_key_matches?(session)
        if @supported_signing_keys.empty?
          # for public clients, require no signing key in the session
          return session.signing_key_id.nil? && session.signing_key_thumbprint.nil?
        else
          # for confidential clients, require a signing key assigned
          thumbprint = @supported_signing_keys[session.signing_key_id]
          thumbprint && thumbprint == session.signing_key_thumbprint
        end
      end

      def validate_client_id(client_id)
        return if client_id == @client_id

        raise SessionError, "Session client_id does not match manager client_id"
      end

      def session_ttl(session)
        return nil if session.renewable?

        if session.pending?
          expires_at = session.authorization_expires_at
          raise SessionError, "Pending session has no authorization deadline" unless expires_at
        else
          expires_at = session.tokens.expires_at
        end

        remaining = expires_at - Time.now
        raise SessionError, "Session has expired" unless remaining.positive?

        remaining.ceil
      end
    end
  end
end
