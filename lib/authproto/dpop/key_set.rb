# frozen_string_literal: true

require 'jose'
require 'json'

require_relative '../dpop'
require_relative '../errors'

module AuthProto
  module DPoP

    #
    # Manages ES256 keypair generation and storage for DPoP proofs.
    # Provides functionality to generate new keys and store them securely.
    # Uses JOSE for cryptographic operations and key format handling.
    #

    class KeySet

      # Error raised when key operations fail
      class KeyError < AuthProto::Error; end

      # Elliptic curve used for DPoP signing keys.
      # @return [String]
      CURVE = "P-256"

      # Private EC P-256 keypair used for signing.
      # @return [JOSE::JWK]
      attr_reader :key

      # Creates a new KeySet instance with an optional existing keypair
      #
      # @param key [JOSE::JWK, nil] Optional existing keypair to use
      # @raise [KeyError] if the provided key is invalid
      #
      def initialize(key = nil)
        @key = key || generate_keypair
        validate_keypair
      end

      # Exports the public key for embedding in a DPoP proof.
      #
      # @return [Hash{String => Object}] public JWK without private key material
      # @raise [KeyError] if public-key export fails
      #
      def public_jwk
        @key.to_public_map.to_h
      rescue StandardError => e
        raise KeyError, "Failed to export public key: #{e.message}"
      end

      # Signs a JSON payload with the supplied protected JWS header and ES256.
      # Hash keys are recursively converted to strings. The algorithm is forced to `ES256`.
      #
      # @param header [Hash{String, Symbol => Object}] protected JOSE header fields
      # @param payload [Hash{String, Symbol => Object}] JWT claims to JSON-encode
      # @return [JOSE::SignedBinary] compact JWS (a string subclass)
      # @raise [KeyError] if encoding or signing fails
      #
      def sign_segments(header, payload)
        # Deep transform all keys to strings to avoid symbol comparison issues
        header = deep_stringify_keys(header)
        payload = deep_stringify_keys(payload)

        # Configure JOSE to use ES256 for signing
        signing_config = { 'alg' => ALGORITHM }

        # Merge our header with JOSE's required fields
        full_header = header.merge(signing_config)

        # Convert payload to JSON string before signing
        payload_json = JSON.generate(payload)

        # Create the JWS with our header and payload
        jws = @key.sign(payload_json, full_header)

        # Get the compact serialization
        jws.compact
      rescue StandardError => e
        raise KeyError, "Failed to sign segments: #{e.message}"
      end

      # Exports this keypair as a JOSE map.
      #
      # @param include_private [Boolean] include secret `d` key material when `true`
      # @return [JOSE::Map] JWK fields; call `to_h` for a Ruby hash
      # @raise [KeyError] if export fails
      #
      def to_jwk(include_private: false)
        key = include_private ? @key : @key.to_public
        key.to_map
      rescue StandardError => e
        raise KeyError, "Failed to export key: #{e.message}"
      end

      # Imports an EC P-256 JWK and validates that it can sign and verify.
      #
      # @param jwk [Hash{String => Object}, JOSE::Map] JWK including private key material
      # @return [KeySet] imported key manager
      # @raise [KeyError] if import or key validation fails
      #
      def self.from_jwk(jwk)
        key = JOSE::JWK.from_map(jwk)
        new(key)
      rescue StandardError => e
        raise KeyError, "Failed to import key: #{e.message}"
      end


      private

      def generate_keypair
        JOSE::JWK.generate_key([:ec, CURVE])
      rescue StandardError => e
        raise KeyError, "Failed to generate keypair: #{e.message}"
      end

      def sign(data)
        @key.sign(data, { 'alg' => ALGORITHM }).compact
      rescue StandardError => e
        raise KeyError, "Failed to sign data: #{e.message}"
      end

      def deep_stringify_keys(obj)
        case obj
        when Hash
          obj.each_with_object({}) do |(k, v), hash|
            hash[k.to_s] = deep_stringify_keys(v)
          end
        when Array
          obj.map { |v| deep_stringify_keys(v) }
        else
          obj
        end
      end

      def verify(signed_jws)
        verified, payload, = @key.verify(signed_jws)
        verified
      rescue StandardError => e
        raise KeyError, "Failed to verify signature: #{e.message}"
      end

      def validate_keypair
        raise KeyError, "Invalid key type: #{@key.kty}, must be :ec" unless @key.kty.is_a?(JOSE::JWK::KTY_EC)

        curve = @key.to_map['crv']
        raise KeyError, "Invalid curve: #{curve}, must be #{CURVE}" unless curve == CURVE

        # Verify we can perform basic operations
        test_data = 'test'
        signed = sign(test_data)
        raise KeyError, "Key validation failed: signature verification error" unless verify(signed)
      rescue StandardError => e
        raise KeyError, "Key validation failed: #{e.message}"
      end
    end
  end
end
