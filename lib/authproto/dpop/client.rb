# frozen_string_literal: true

require 'uri'

module AuthProto

  #
  # Key management, per-request proofs and server-origin nonces for DPoP authentication.
  #

  module DPoP

    # High-level client for managing DPoP operations. Integrates key management,
    # proof generation, and nonce tracking to provide a complete DPoP client
    # implementation according to RFC 9449.
    #
    # This client handles:
    # - Key management for signing proofs
    # - Proof generation for HTTP requests
    # - Nonce tracking across servers
    # - Header construction for requests
    # - Response processing for nonce updates
    #

    class Client

      # Error raised for DPoP client operations
      class Error < AuthProto::Error; end

      # Key manager used to sign proofs.
      # @return [KeyManager]
      attr_reader :key_manager

      # Generator for per-request DPoP JWTs.
      # @return [ProofGenerator]
      attr_reader :proof_generator

      # Persistent nonce store, indexed by server origin.
      # @return [NonceManager]
      attr_reader :nonce_manager

      # Creates DPoP signing, proof and nonce managers.
      #
      # @param key_manager [KeyManager, nil] existing key manager, or `nil` to generate a keypair
      # @param nonce_ttl [Integer, nil] stored nonce lifetime in seconds, or the nonce manager's default
      # @raise [KeyManager::KeyError] if key generation fails
      # @raise [ProofGenerator::ProofError] if the key manager is invalid
      # @raise [ArgumentError] if the encryption master key is not valid Base64
      #
      def initialize(key_manager: nil, nonce_ttl: nil)
        @key_manager = key_manager || KeyManager.new
        @nonce_manager = NonceManager.new(ttl: nonce_ttl)
        @proof_generator = ProofGenerator.new(@key_manager)
      end

      # Generates a fresh DPoP proof using a supplied or stored nonce for the origin.
      #
      # @param http_method [String] HTTP method, converted to uppercase
      # @param http_uri [String] absolute HTTP(S) URL; callers should omit the query and fragment
      # @param access_token [String, nil] token to bind with an `ath` claim
      # @param nonce [String, nil] explicit nonce; `nil` looks up the origin's stored nonce
      # @return [JOSE::SignedBinary] compact signed DPoP JWT
      # @raise [Error] if URI parsing, nonce lookup or signing fails
      #
      def generate_proof(http_method:, http_uri:, access_token: nil, nonce: nil)
        uri = URI(http_uri)
        server_url = "#{uri.scheme}://#{uri.host}#{":#{uri.port}" if uri.port != uri.default_port}"

        # Use provided nonce or get one from the manager
        nonce ||= @nonce_manager.get(server_url)

        @proof_generator.generate(
          http_method: http_method,
          http_uri: http_uri,
          nonce: nonce,
          access_token: access_token
        )
      rescue StandardError => e
        raise Error, "Failed to generate proof: #{e.message}"
      end

      # Stores a `DPoP-Nonce` response header for future requests to the same origin.
      # Header names are compared case-insensitively. Missing headers/nonces are ignored.
      #
      # @param response_headers [Hash{String => String}, nil] response headers, or `nil`
      # @param server_url [String] request URL whose origin owns the nonce
      # @return [void]
      # @raise [Error] if nonce validation or persistence fails
      #
      def process_response(response_headers, server_url)
        return unless response_headers

        # Look for DPoP-Nonce header (case insensitive)
        nonce = response_headers.find { |k, _| k.downcase == "dpop-nonce" }&.last
        return unless nonce

        # Store new nonce for future requests
        @nonce_manager.update(nonce: nonce, server_url: server_url)
      rescue StandardError => e
        raise Error, "Failed to process response: #{e.message}"
      end

      # Wraps a proof in an HTTP header hash.
      #
      # @param proof [String] signed DPoP JWT
      # @return [Hash{String => String}] a single `DPoP` header
      #
      def request_headers(proof)
        {
          "DPoP" => proof
        }
      end

      # Exports the current public signing key.
      #
      # @return [Hash{String => Object}] public JWK
      # @raise [KeyManager::KeyError] if public-key export fails
      #
      def public_key
        @key_manager.public_jwk
      end

      # Exports the current DPoP key for persistence or inspection.
      #
      # @param include_private [Boolean] include the private key needed to restore the same identity
      # @return [JOSE::Map] JWK fields; call `to_h` for a Ruby hash
      # @raise [KeyManager::KeyError] if key export fails
      #
      def export_key(include_private: false)
        @key_manager.to_jwk(include_private: include_private)
      end


      private

      def extract_nonce(headers)
        # Headers can be hash with string or symbol keys, or http headers object
        headers = headers.to_h if headers.respond_to?(:to_h)

        # Try different common header key formats
        nonce = headers["DPoP-Nonce"] || headers["dpop-nonce"] || headers[:dpop_nonce]

        nonce&.strip
      end

      def origin_for_uri(uri)
        port = uri.port
        port = nil if (uri.scheme == "https" && port == 443) || (uri.scheme == "http" && port == 80)

        origin = "#{uri.scheme}://#{uri.host}"
        origin = "#{origin}:#{port}" if port
        origin
      end
    end
  end
end
