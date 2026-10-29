# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'securerandom'
require 'uri'

require_relative '../errors'
require_relative 'key_manager'

module AuthProto
  module DPoP

    #
    # Creates and manages DPoP proof JWTs according to RFC 9449.
    # DPoP proofs are used to prove possession of a key when making
    # HTTP requests. Each proof is a JWT that includes details about
    # the request and is signed by the DPoP key.
    #

    class ProofGenerator

      # Error raised for proof generation/validation issues
      class ProofError < AuthProto::Error; end

      # Key manager used to sign proofs.
      # @return [KeyManager]
      attr_reader :key_manager

      # Creates a new ProofGenerator instance
      #
      # @param key_manager [KeyManager] Key manager to use for signing proofs
      # @raise [ProofError] if key_manager is invalid
      #
      def initialize(key_manager)
        raise ProofError, "key_manager is required" unless key_manager
        raise ProofError, "invalid key_manager type" unless key_manager.is_a?(KeyManager)

        @key_manager = key_manager
      end

      # Builds and signs a fresh DPoP JWT with `jti`, `htm`, `htu` and `iat` claims.
      #
      # A nonce and access-token hash are added when requested. The URI normalizer removes
      # fragments and default ports; callers must remove query strings before calling.
      #
      # @param http_method [String] nonempty HTTP method, converted to uppercase
      # @param http_uri [String] absolute HTTP(S) request URL without a query string
      # @param nonce [String, nil] server-provided nonce to include
      # @param access_token [String, nil] access token to bind to the proof
      # @param ath [Boolean, nil] include an access-token hash; `nil` enables it when a token is supplied
      # @return [JOSE::SignedBinary] compact signed DPoP JWT
      # @raise [ProofError] if input validation or proof generation fails
      #
      def generate(http_method:, http_uri:, nonce: nil, access_token: nil, ath: nil)
        validate_inputs(http_method, http_uri)
        ath = !access_token.nil? if ath.nil?

        header = build_header
        payload = build_payload(
          http_method: http_method,
          http_uri: http_uri,
          nonce: nonce,
          access_token: access_token,
          include_ath: ath
        )

        key_manager.sign_segments(header, payload)
      rescue StandardError => e
        raise ProofError, "Failed to generate proof: #{e.message}"
      end

      private

      def validate_inputs(http_method, http_uri)
        raise ProofError, "http_method is required" if http_method.nil? || http_method.empty?
        raise ProofError, "http_uri is required" if http_uri.nil? || http_uri.empty?

        uri = URI(http_uri)
        raise ProofError, "invalid http_uri" unless uri.is_a?(URI::HTTP)
      rescue URI::InvalidURIError => e
        raise ProofError, "invalid http_uri: #{e.message}"
      end

      def build_header
        {
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: key_manager.public_jwk.to_h
        }
      end

      def build_payload(http_method:, http_uri:, nonce: nil, access_token: nil, include_ath: nil)
        payload = {
          "jti" => SecureRandom.uuid,
          "htm" => http_method.upcase,
          "htu" => normalize_uri(http_uri),
          "iat" => Time.now.to_i
        }

        # Add the nonce if provided
        payload["nonce"] = nonce if nonce

        # Add access token hash if needed
        payload["ath"] = generate_access_token_hash(access_token) if access_token && include_ath

        payload
      end

      def normalize_uri(uri)
        uri = URI(uri)
        # Remove default ports
        uri.port = nil if (uri.scheme == "https" && uri.port == 443) || (uri.scheme == "http" && uri.port == 80)
        uri.fragment = nil
        uri.to_s
      end

      def generate_access_token_hash(access_token)
        digest = OpenSSL::Digest::SHA256.digest(access_token)
        Base64.urlsafe_encode64(digest, padding: false)
      end
    end
  end
end
