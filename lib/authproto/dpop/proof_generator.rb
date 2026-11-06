# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'securerandom'
require 'uri'

require_relative '../dpop'
require_relative '../errors'
require_relative '../validated_uri'
require_relative 'key_set'

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

      # Builds and signs a fresh DPoP JWT with `jti`, `htm`, `htu` and `iat` claims.
      #
      # Includes a nonce when provided and an access-token hash whenever an access token
      # is supplied. The URI normalizer removes query strings, fragments and default ports.
      #
      # @param key_set [KeySet] key belonging to the session making this request
      # @param method [String] nonempty HTTP method, converted to uppercase
      # @param uri [String, URI::HTTPS] absolute HTTPS request URL
      # @param nonce [String, nil] server-provided nonce to include
      # @param access_token [String, nil] access token to bind to the proof
      # @return [JOSE::SignedBinary] compact signed DPoP JWT
      # @raise [ProofError] if input validation or proof generation fails
      #
      def generate(key_set:, method:, uri:, nonce: nil, access_token: nil)
        raise ProofError, "invalid key_set type" unless key_set.is_a?(KeySet)

        validate_inputs(method, uri)

        header = build_header(key_set)
        payload = build_payload(
          method: method,
          uri: uri,
          nonce: nonce,
          access_token: access_token
        )

        key_set.sign_segments(header, payload)
      rescue StandardError => e
        raise ProofError, "Failed to generate proof: #{e.message}"
      end


      private

      def validate_inputs(method, uri)
        raise ProofError, "method is required" if method.nil? || method.empty?
        raise ProofError, "uri is required" if uri.nil? || uri == ''

        parsed_uri = ValidatedURI.new(uri)
        raise ProofError, "uri must use HTTPS" unless parsed_uri.scheme == 'https'
      rescue URI::InvalidURIError => e
        raise ProofError, "invalid uri: #{e.message}"
      end

      def build_header(key_set)
        {
          typ: 'dpop+jwt',
          alg: ALGORITHM,
          jwk: key_set.public_jwk
        }
      end

      def build_payload(method:, uri:, nonce: nil, access_token: nil)
        payload = {
          'jti' => SecureRandom.uuid,
          'htm' => method.upcase,
          'htu' => normalize_uri(uri),
          'iat' => Time.now.to_i
        }

        # Add the nonce if provided
        payload['nonce'] = nonce if nonce

        # Bind the proof to the access token whenever one is supplied
        payload['ath'] = generate_access_token_hash(access_token) unless access_token.nil?

        payload
      end

      def normalize_uri(uri)
        uri = URI(uri).dup

        # Remove default ports
        uri.port = nil if uri.scheme == 'https' && uri.port == 443

        uri.query = nil
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
