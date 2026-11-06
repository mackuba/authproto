# frozen_string_literal: true

require 'json'
require 'uri'

require_relative '../errors'
require_relative '../http_helpers'
require_relative 'nonce_manager'
require_relative 'proof_generator'

module AuthProto

  #
  # Shared proof generation and server-origin nonces for DPoP authentication.
  #

  module DPoP

    #
    # Shared DPoP client using session-owned signing keys and nonces scoped to
    # each session and server origin. Generates RFC 9449 proofs, processes nonce
    # updates, and detects nonce challenges. Response processing requires a nonce
    # on every DPoP response, as required by the AT Protocol OAuth profile.
    #

    class Client
      include HTTPHelpers

      # Error raised for DPoP client operations
      class Error < AuthProto::Error; end

      # Generator for per-request DPoP JWTs.
      # @return [ProofGenerator]
      attr_reader :proof_generator

      # Persistent nonce store, indexed by session and server origin.
      # @return [NonceManager]
      attr_reader :nonce_manager

      # Creates a shared proof generator and nonce storage scoped to sessions and server origins.
      #
      # @param nonce_ttl [Integer, nil] stored nonce lifetime in seconds; `nil` uses {Configuration#dpop_nonce_lifetime}
      # @raise [ArgumentError] if the encryption master key is not valid Base64
      #
      def initialize(nonce_ttl: nil)
        @nonce_manager = NonceManager.new(ttl: nonce_ttl)
        @proof_generator = ProofGenerator.new
      end

      # Generates a fresh DPoP proof using the stored nonce for the session and origin, if available.
      #
      # @param session [State::Session] session whose DPoP key signs the request
      # @param method [String] HTTP method, converted to uppercase
      # @param uri [String, URI::HTTPS] absolute HTTPS request URL; query and fragment are omitted from the signed `htu`
      # @param access_token [String, nil] token to bind with an `ath` claim
      # @return [JOSE::SignedBinary] compact signed DPoP JWT
      # @raise [Error] if URI parsing, nonce lookup or signing fails
      #
      def generate_proof(session:, method:, uri:, access_token: nil)
        nonce = @nonce_manager.get(url: uri, session_id: session.session_id)

        @proof_generator.generate(
          key_set: session.dpop_key,
          method: method,
          uri: uri,
          nonce: nonce,
          access_token: access_token
        )
      rescue StandardError => e
        raise Error, "Failed to generate proof: #{e.message}"
      end

      # Stores a `DPoP-Nonce` response header for future requests to the same origin.
      # Call after every DPoP HTTP attempt, before accepting a result or deciding to retry.
      # Header names are case-insensitive; missing, malformed and duplicate nonces are rejected.
      #
      # @param session_id [String] session that made the request
      # @param response [Hash{Symbol => Object}] HTTP response with `:status`, `:headers`, and `:body`
      # @param url [String, URI::HTTPS] URL of the request that produced the response
      # @return [void]
      # @raise [Error] if nonce validation or persistence fails
      #
      def process_response(response, url:, session_id:)
        validate_response_fields(response)

        if response[:headers].keys.count { |name| name.casecmp?('DPoP-Nonce') } > 1
          raise Error, "Multiple DPoP-Nonce headers"
        end

        nonce = response_header(response, 'DPoP-Nonce')

        if nonce.nil? || nonce == ''
          raise Error, "Missing DPoP-Nonce header"
        end

        # Store new nonce for future requests
        @nonce_manager.update(nonce: nonce, url: url, session_id: session_id)
      rescue StandardError => e
        raise Error, "Failed to process response: #{e.message}"
      end

      # Detects a nonce challenge without treating other errors as nonce challenges.
      #
      # Recognizes HTTP 400 JSON errors and an HTTP 401 DPoP authentication
      # challenge. Header/parameter names and the scheme are case-insensitive;
      # error values are case-sensitive. Multiple DPoP challenges are treated as ambiguous.
      #
      # @param response [Hash{Symbol => Object}] HTTP response with status, headers and body
      # @return [Boolean] whether the response requests a retry with a server nonce
      # @raise [Error] if the response or its headers have an invalid type
      #
      def has_nonce_error?(response)
        validate_response_fields(response)

        case response_status(response)
        when 400
          return false unless response[:body].is_a?(String)

          begin
            data = JSON.parse(response[:body])
            data.is_a?(Hash) && data['error'] == DPoP::ERROR_USE_NONCE
          rescue JSON::ParserError
            false
          end
        when 401
          challenge = response_header(response, 'WWW-Authenticate')
          nonce_challenge?(challenge)
        else
          false
        end
      end

      # Runs a DPoP request and retries once if the server requests a new nonce.
      # Processes every response before returning it or invoking the block again.
      # The block must build a fresh proof and send the request on each invocation;
      # the initial proof may already include a cached nonce.
      #
      # @param session_id [String] ID of the session making the request
      # @param url [String, URI::HTTPS] request URL whose origin owns the nonce
      # @yield sends one HTTP request using a fresh DPoP proof
      # @yieldreturn [Hash{Symbol => Object}] HTTP response with status, headers and body
      # @return [Hash{Symbol => Object}] final response, including any remaining error
      # @raise [Error] if a response lacks a valid nonce or nonce persistence fails
      #
      def with_nonce_handling(session_id, url)
        response = yield

        process_response(response, url: url, session_id: session_id)

        if has_nonce_error?(response)
          response = yield

          process_response(response, url: url, session_id: session_id)
        end

        response
      end


      private

      def validate_response_fields(response)
        raise Error, "Expected a response hash" unless response.is_a?(Hash)

        missing_keys = %i[status headers body].reject { |key| response.key?(key) }

        unless missing_keys.empty?
          raise Error, "Missing response keys: #{missing_keys.join(', ')}"
        end

        raise Error, "Missing or invalid response headers" unless response[:headers].is_a?(Hash)
      end

      def nonce_challenge?(challenge)
        authentication_challenge(challenge, scheme: 'DPoP')&.fetch('error', nil) == DPoP::ERROR_USE_NONCE
      end
    end
  end
end
