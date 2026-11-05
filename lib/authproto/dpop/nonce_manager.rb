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
      # @param url [String] HTTPS URL whose origin owns the nonce
      # @return [void]
      # @raise [NonceError] if inputs are invalid or storage reports failure
      # @raise [Storage::StorageError] if backend validation or storage fails
      #
      def update(nonce:, url:, session_id:)
        validate_session_id(session_id)
        validate_inputs(nonce, url)
        origin = normalize_url(url)

        stored_nonce = StoredNonce.new(nonce, origin)
        serialized = @serializer.serialize(stored_nonce)

        key = Storage::KeyBuilder.nonce_key(session_id, origin)
        return if AuthProto.storage.set(key, serialized, ttl: @ttl)

        raise NonceError, "Failed to store nonce"
      end

      # Retrieves the current nonce for a session and URL's origin.
      #
      # @param session_id [String] nonempty OAuth session identifier
      # @param url [String] HTTPS URL whose origin owns the nonce
      # @return [String, nil] stored nonce, or `nil` when missing/expired according to storage TTL
      # @raise [NonceError] if the session ID or URL is invalid, or serialized data cannot be read
      # @raise [Storage::StorageError] if storage retrieval fails
      #
      def get(url:, session_id:)
        validate_session_id(session_id)
        validate_url(url)
        origin = normalize_url(url)
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
      # @param url [String] HTTPS URL whose origin owns the nonce
      # @return [Boolean] backend deletion status
      # @raise [NonceError] if the session ID or URL is invalid
      # @raise [Storage::StorageError] if deletion fails
      #
      def clear(url:, session_id:)
        validate_session_id(session_id)
        validate_url(url)
        origin = normalize_url(url)
        key = Storage::KeyBuilder.nonce_key(session_id, origin)
        AuthProto.storage.delete(key)
      end

      private

      def validate_session_id(session_id)
        return if session_id.is_a?(String) && !session_id.empty?

        raise NonceError, "session_id must be a nonempty string"
      end

      def normalize_url(url)
        uri = URI(url)
        port = uri.port
        port = nil if uri.scheme == 'https' && port == 443

        origin = "#{uri.scheme}://#{uri.host}"
        origin = "#{origin}:#{port}" if port
        origin
      end

      def validate_inputs(nonce, url)
        raise NonceError, "nonce must not be empty" if nonce.to_s == ''
        raise NonceError, "Invalid DPoP nonce" unless nonce.is_a?(String)
        raise NonceError, "Invalid characters in the DPoP nonce" unless nonce.ascii_only? && nonce =~ NONCE_REGEXP

        validate_url(url)
      end

      def validate_url(url)
        raise NonceError, "url is required" if url.nil? || url.empty?

        uri = ValidatedURI.new(url)

        raise NonceError, "url must be HTTPS" unless uri.scheme == 'https'
      rescue URI::InvalidURIError => e
        raise NonceError, "invalid url: #{e.message}"
      end
    end
  end
end
