# frozen_string_literal: true

require 'uri'

require_relative '../configuration'
require_relative '../errors'
require_relative '../serialization/stored_nonce'
require_relative '../storage/key_builder'
require_relative '../validated_uri'
require_relative 'stored_nonce'

module AuthProto
  module DPoP

    #
    # Manages DPoP nonces provided by servers during the OAuth flow.
    # Tracks separate nonces for each session and server using persistent storage.
    # Thread-safe to handle concurrent requests.
    #

    class NonceManager

      # Regexp for checking the nonce value for invalid characters
      NONCE_REGEXP = /\A[\x21\x23-\x5B\x5D-\x7E]+\z/

      # Error for nonce-related issues
      class NonceError < AuthProto::Error; end

      # Creates a nonce manager using the global storage backend.
      #
      # @param ttl [Integer, nil] nonce lifetime in seconds; `nil` uses {Configuration#dpop_nonce_lifetime}
      # @raise [ArgumentError] if the master encryption key is not valid Base64
      #
      def initialize(ttl: nil)
        @ttl = ttl || AuthProto.configuration.dpop_nonce_lifetime
        @serializer = Serialization::StoredNonce.new
      end

      # Stores a nonce for the session and URL's origin, replacing any previous value.
      #
      # @param nonce [String] server-provided nonce using RFC 9449's `1*NQCHAR` syntax
      # @param session_id [String] nonempty OAuth session identifier
      # @param server_url [String] HTTPS URL, or HTTP URL with host `localhost`
      # @return [void]
      # @raise [NonceError] if inputs are invalid or storage reports failure
      # @raise [Storage::StorageError] if backend validation or storage fails
      #
      def update(nonce:, server_url:, session_id:)
        validate_session_id(session_id)
        validate_inputs(nonce, server_url)
        origin = normalize_server_url(server_url)

        stored_nonce = StoredNonce.new(nonce, origin)
        serialized = @serializer.serialize(stored_nonce)

        key = Storage::KeyBuilder.nonce_key(session_id, origin)
        return if AuthProto.storage.set(key, serialized, ttl: @ttl)

        raise NonceError, "Failed to store nonce"
      end

      # Retrieves the current nonce for a session and URL's origin.
      #
      # @param session_id [String] nonempty OAuth session identifier
      # @param server_url [String] HTTPS URL, or HTTP URL with host `localhost`
      # @return [String, nil] stored nonce, or `nil` when missing/expired according to storage TTL
      # @raise [NonceError] if the session ID or URL is invalid, or serialized data cannot be read
      # @raise [Storage::StorageError] if storage retrieval fails
      #
      def get(server_url:, session_id:)
        validate_session_id(session_id)
        validate_server_url(server_url)
        origin = normalize_server_url(server_url)
        key = Storage::KeyBuilder.nonce_key(session_id, origin)

        stored = AuthProto.storage.get(key)
        return nil unless stored

        begin
          stored_nonce = @serializer.deserialize(stored)
          stored_nonce.value
        rescue Serialization::Error => e
          raise NonceError, "Failed to deserialize nonce: #{e.message}"
        end
      end

      # Removes the stored nonce for a session and URL's origin.
      #
      # @param session_id [String] nonempty OAuth session identifier
      # @param server_url [String] HTTPS URL, or HTTP URL with host `localhost`
      # @return [Boolean] backend deletion status
      # @raise [NonceError] if the session ID or URL is invalid
      # @raise [Storage::StorageError] if deletion fails
      #
      def clear(server_url:, session_id:)
        validate_session_id(session_id)
        validate_server_url(server_url)
        origin = normalize_server_url(server_url)
        key = Storage::KeyBuilder.nonce_key(session_id, origin)
        AuthProto.storage.delete(key)
      end

      private

      def validate_session_id(session_id)
        return if session_id.is_a?(String) && !session_id.empty?

        raise NonceError, "session_id must be a nonempty string"
      end

      def normalize_server_url(url)
        uri = URI(url)
        port = uri.port
        port = nil if (uri.scheme == 'https' && port == 443) ||
                      (uri.scheme == 'http' && port == 80)

        origin = "#{uri.scheme}://#{uri.host}"
        origin = "#{origin}:#{port}" if port
        origin
      end

      def validate_inputs(nonce, server_url)
        raise NonceError, "nonce must not be empty" if nonce.to_s == ''
        raise NonceError, "Invalid DPoP nonce" unless nonce.is_a?(String)
        raise NonceError, "Invalid characters in the DPoP nonce" unless nonce.ascii_only? && nonce =~ NONCE_REGEXP

        validate_server_url(server_url)
      end

      def validate_server_url(server_url)
        raise NonceError, "server_url is required" if server_url.nil? || server_url.empty?

        uri = ValidatedURI.new(server_url)

        # Allow HTTP for localhost only
        if uri.host != 'localhost' && uri.scheme != 'https'
          raise NonceError, "server_url must be HTTPS (except for localhost)"
        end
      rescue URI::InvalidURIError => e
        raise NonceError, "invalid server_url: #{e.message}"
      end
    end
  end
end
