# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'securerandom'

require_relative 'errors'

module AuthProto

  #
  # AES-GCM envelopes and context-specific key derivation for stored OAuth secrets.
  #

  module Encryption

    # Base class for encryption and key-configuration failures.
    class Error < AuthProto::Error; end

    # Raised when a required key derivation context is missing.
    class ConfigurationError < Error; end

    # Raised when plaintext inputs are invalid or encryption fails.
    class EncryptionError < Error; end

    # Raised when an encrypted envelope cannot be decoded, authenticated or decrypted.
    class DecryptionError < Error; end

    #
    # HKDF implementation based on RFC 5869
    #

    module HKDF

      # Derives key bytes with HKDF-SHA256 (RFC 5869).
      #
      # @param secret [#to_s] input key material
      # @param salt [String] extraction salt; an empty string uses 32 zero bytes
      # @param info [String] application/context information for expansion
      # @param length [Integer] number of output bytes to derive
      # @return [String] derived binary key material
      #
      def self.derive(secret, salt:, info:, length:)
        # 1. extract
        prk = OpenSSL::HMAC.digest(
          OpenSSL::Digest.new("SHA256"),
          salt.empty? ? "\x00" * 32 : salt,
          secret.to_s
        )

        # 2. expand
        n = (length.to_f / 32).ceil
        t = [""]
        output = ""
        1.upto(n) do |i|
          t[i] = OpenSSL::HMAC.digest(
            OpenSSL::Digest.new("SHA256"),
            prk,
            t[i - 1] + info + [i].pack("C")
          )
          output += t[i]
        end
        output[0, length]
      end
    end

    #
    # Core encryption service - used internally by serializers
    #

    class Service

      # OpenSSL cipher name used for authenticated encryption.
      # @return [String]
      CIPHER = "aes-256-gcm"

      # Version stored in encrypted field envelopes.
      # @return [Integer]
      VERSION = 1

      # Creates an encryption service backed by {KeyProvider}.
      # @raise [ArgumentError] if the configured master key is not valid Base64
      #
      def initialize
        @key_provider = KeyProvider.new
      end

      # Encrypts a string representation of data using AES-256-GCM and a context-derived key.
      #
      # The context is also authenticated; decryption must use the same context.
      #
      # @param data [#to_s] non-`nil` plaintext value, converted to a string
      # @param context [String] nonempty context used for key derivation and authentication
      # @return [Hash{Symbol => Integer, String}] envelope with `:version` (Integer) and Base64 `:iv`, `:data`, `:tag` (String)
      # @raise [EncryptionError] if inputs are invalid or encryption fails
      #
      def encrypt(data, context:)
        validate_encryption_inputs(data, context)

        iv = SecureRandom.random_bytes(12)

        cipher = OpenSSL::Cipher.new(CIPHER)
        cipher.encrypt
        cipher.key = @key_provider.key_for_context(context)
        cipher.iv = iv
        cipher.auth_data = context.to_s

        encrypted = cipher.update(data.to_s) + cipher.final
        auth_tag = cipher.auth_tag

        {
          version: VERSION,
          iv: Base64.strict_encode64(iv),
          data: Base64.strict_encode64(encrypted),
          tag: Base64.strict_encode64(auth_tag)
        }
      rescue StandardError => e
        raise EncryptionError, "Encryption failed: #{e.message}"
      end

      # Authenticates and decrypts an envelope returned by {#encrypt}.
      #
      # @param encrypted [Hash{Symbol => Integer, String}] symbol-keyed `:version`, `:iv`, `:data`, `:tag` envelope
      # @param context [String] same nonempty context used for encryption
      # @return [String] plaintext bytes
      # @raise [DecryptionError] if the context, key, version, encoding or authentication tag is invalid
      #
      def decrypt(encrypted, context:)
        validate_decryption_inputs(encrypted, context)
        validate_encrypted_data(encrypted)

        iv = Base64.strict_decode64(encrypted[:iv])
        data = Base64.strict_decode64(encrypted[:data])
        auth_tag = Base64.strict_decode64(encrypted[:tag])

        cipher = OpenSSL::Cipher.new(CIPHER)
        cipher.decrypt
        cipher.key = @key_provider.key_for_context(context)
        cipher.iv = iv
        cipher.auth_tag = auth_tag
        cipher.auth_data = context.to_s

        cipher.update(data) + cipher.final
      rescue ArgumentError => e
        raise DecryptionError, "Invalid encrypted data format: #{e.message}"
      rescue StandardError => e
        raise DecryptionError, "Decryption failed: #{e.message}"
      end


      private

      def validate_encryption_inputs(data, context)
        raise EncryptionError, "Data cannot be nil" if data.nil?
        raise EncryptionError, "Context cannot be nil" if context.nil?
        raise EncryptionError, "Context must be a string" unless context.is_a?(String)
        raise EncryptionError, "Context cannot be empty" if context.empty?
      end

      def validate_decryption_inputs(encrypted, context)
        raise DecryptionError, "Encrypted data cannot be nil" if encrypted.nil?
        raise DecryptionError, "Context cannot be nil" if context.nil?
        raise DecryptionError, "Context must be a string" unless context.is_a?(String)
        raise DecryptionError, "Context cannot be empty" if context.empty?
      end

      def validate_encrypted_data(encrypted)
        raise DecryptionError, "Invalid encrypted data format" unless encrypted.is_a?(Hash)

        unless encrypted[:version] == VERSION
          raise DecryptionError, "Unsupported encryption version: #{encrypted[:version]}"
        end

        %i[iv data tag].each do |field|
          raise DecryptionError, "Missing required field: #{field}" unless encrypted[field].is_a?(String)
        end
      end
    end

    #
    # Handles key management and derivation
    #

    class KeyProvider

      # Protects creation of the process fallback master key.
      # @return [Mutex]
      EPHEMERAL_KEY_MUTEX = Mutex.new

      # Returns a randomly generated master key shared by this class within the process.
      #
      # The key is cached under a mutex and is lost when the process exits.
      #
      # @return [String] 32 bytes of binary key material
      #
      def self.ephemeral_master_key
        EPHEMERAL_KEY_MUTEX.synchronize do
          @ephemeral_master_key ||= SecureRandom.random_bytes(32)
        end
      end

      # Loads the master key from `ATPROTO_MASTER_KEY` or uses the process fallback.
      #
      # Set the environment variable to a Base64-encoded master secret, typically
      # 32 random bytes. Context-specific AES-256 keys are derived from that secret.
      # Without it, a warning is emitted and {KeyProvider.ephemeral_master_key} is used;
      # data encrypted with that fallback cannot be recovered after a restart.
      #
      # @raise [ArgumentError] if `ATPROTO_MASTER_KEY` is not valid Base64
      #
      def initialize
        @master_key = load_master_key
      end

      # Derives a 32-byte key specific to an encryption context.
      #
      # @param context [String] context label, such as `data.access_token`
      # @return [String] context-specific binary key
      # @raise [ConfigurationError] if context is `nil`
      #
      def key_for_context(context)
        raise ConfigurationError, "Context is required" if context.nil?

        HKDF.derive(
          @master_key,
          salt: salt_for_context(context),
          info: "atproto-#{context}",
          length: 32
        )
      end


      private

      def load_master_key
        # Try environment variable first
        key = ENV.fetch("ATPROTO_MASTER_KEY", nil)
        return Base64.strict_decode64(key) if key

        # Generate and store a random key if not configured
        warn "WARNING: Using randomly generated encryption key - tokens will not persist across restarts"
        self.class.ephemeral_master_key
      end

      def salt_for_context(context)
        OpenSSL::Digest.digest("SHA256", "atproto-salt-#{context}")
      end
    end
  end
end
