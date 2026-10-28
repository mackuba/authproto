# frozen_string_literal: true

require 'base64'
require 'json'
require 'openssl'

module AuthProto
  module DPoP

    #
    # Manages ES256 keypair generation and storage for DPoP proofs.
    # Provides functionality to generate new keys and store them securely.
    # Uses JOSE for cryptographic operations and key format handling.
    #

    class KeyManager

      # Error raised when key operations fail
      class KeyError < AuthProto::Error; end

      # Elliptic curve used for DPoP signing keys.
      # @return [String]
      CURVE = "P-256"

      # JWS signing algorithm used for DPoP proofs.
      # @return [String]
      ALGORITHM = "ES256"

      # Private EC P-256 keypair used for signing.
      # @return [JOSE::JWK]
      attr_reader :keypair

      # Creates a new KeyManager instance with an optional existing keypair
      #
      # @param keypair [JOSE::JWK, nil] Optional existing keypair to use
      # @raise [KeyError] if the provided keypair is invalid
      #
      def initialize(keypair = nil)
        @keypair = keypair || generate_keypair
        validate_keypair
      end

      # Generates a new ES256 keypair for DPoP usage
      #
      # @return [JOSE::JWK] The newly generated keypair
      # @raise [KeyError] if key generation fails
      #
      def generate_keypair
        # Generate base keypair
        base_key = JOSE::JWK.generate_key([:ec, CURVE])
        base_map = base_key.to_map

        # Create new map with all required properties
        key_map = {
          "kty" => base_map["kty"],
          "crv" => base_map["crv"],
          "x" => base_map["x"],
          "y" => base_map["y"],
          "d" => base_map["d"],
          "use" => "sig",
          "kid" => generate_kid(base_map)
        }

        # Create new JWK with all properties
        JOSE::JWK.from_map(key_map)
      rescue StandardError => e
        raise KeyError, "Failed to generate keypair: #{e.message}"
      end

      # Exports the public key with `use: sig` and a key ID.
      #
      # @return [Hash{String => Object}] public JWK without private key material
      # @raise [KeyError] if public-key export fails
      #
      def public_jwk
        jwk = @keypair.to_public.to_map.to_h
        # If somehow the properties aren't set, add them
        jwk["use"] ||= "sig"
        jwk["kid"] ||= generate_kid(jwk)
        jwk
      rescue StandardError => e
        raise KeyError, "Failed to export public key: #{e.message}"
      end

      # Signs bytes with this keypair and returns a compact JWS.
      #
      # @param data [String] payload bytes to sign
      # @return [JOSE::SignedBinary] compact JWS (a string subclass)
      # @raise [KeyError] if signing fails
      #
      def sign(data)
        @keypair.sign(data).compact
      rescue StandardError => e
        raise KeyError, "Failed to sign data: #{e.message}"
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
        signing_config = { "alg" => "ES256" }

        # Merge our header with JOSE's required fields
        full_header = header.merge(signing_config)

        # Convert payload to JSON string before signing
        payload_json = JSON.generate(payload)

        # Create the JWS with our header and payload
        jws = @keypair.sign(payload_json, full_header)

        # Get the compact serialization
        jws.compact
      rescue StandardError => e
        raise KeyError, "Failed to sign segments: #{e.message}"
      end

      # Copies hashes and arrays recursively, converting hash keys to strings.
      #
      # @param obj [Object] input structure or scalar value
      # @return [Object] transformed hash/array, or the original scalar
      #
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

      # Verifies a compact JWS using this keypair.
      #
      # @param signed_jws [String, JOSE::SignedBinary] complete signed JWS
      # @return [Boolean] whether the signature is valid
      # @raise [KeyError] if decoding or verification raises an error
      #
      def verify(signed_jws)
        verified, payload, = @keypair.verify(signed_jws)
        verified
      rescue StandardError => e
        raise KeyError, "Failed to verify signature: #{e.message}"
      end

      # Exports this keypair as a JOSE map.
      #
      # @param include_private [Boolean] include secret `d` key material when `true`
      # @return [JOSE::Map] JWK fields; call `to_h` for a Ruby hash
      # @raise [KeyError] if export fails
      #
      def to_jwk(include_private: false)
        key = include_private ? @keypair : @keypair.to_public
        key.to_map
      rescue StandardError => e
        raise KeyError, "Failed to export key: #{e.message}"
      end

      # Imports an EC P-256 JWK and validates that it can sign and verify.
      #
      # @param jwk [Hash{String => Object}, JOSE::Map] JWK including private key material
      # @return [KeyManager] imported key manager
      # @raise [KeyError] if import or key validation fails
      #
      def self.from_jwk(jwk)
        keypair = JOSE::JWK.from_map(jwk)
        new(keypair)
      rescue StandardError => e
        raise KeyError, "Failed to import key: #{e.message}"
      end

      private

      def generate_kid(jwk)
        # Generate a key ID based on the key's components
        components = [
          jwk["kty"],
          jwk["crv"],
          jwk["x"],
          jwk["y"]
        ].join(":")

        # Create a SHA-256 hash and take first 8 bytes
        digest = OpenSSL::Digest::SHA256.digest(components)
        Base64.urlsafe_encode64(digest[0..7], padding: false)
      end

      # Validates that the keypair meets DPoP requirements
      # @raise [KeyError] if validation fails
      def validate_keypair
        # Check that we have a valid EC key
        raise KeyError, "Invalid key type: #{@keypair.kty}, must be :ec" unless @keypair.kty.is_a?(JOSE::JWK::KTY_EC)

        # Verify the curve
        curve = @keypair.to_map["crv"]
        raise KeyError, "Invalid curve: #{curve}, must be #{CURVE}" unless curve == CURVE

        # Verify we can perform basic operations
        test_data = "test"
        signed = sign(test_data)
        raise KeyError, "Key validation failed: signature verification error" unless verify(signed)
      rescue StandardError => e
        raise KeyError, "Key validation failed: #{e.message}"
      end
    end
  end
end
