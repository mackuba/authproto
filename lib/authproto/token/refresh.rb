# frozen_string_literal: true

require 'jose'
require 'json'
require 'monitor'

require_relative '../configuration'
require_relative '../errors'
require_relative '../http_client'
require_relative '../par'
require_relative '../par/client_assertion'
require_relative '../state/token_set'

module AuthProto

  #
  # Token error types and synchronized refresh-token exchange operations.
  #

  module Token

    #
    # Base error class for token-related errors
    #

    class Error < AuthProto::Error

      # Kind of token associated with the failure.
      # @return [String]
      attr_reader :token_type

      # Machine-readable token error code.
      # @return [String]
      attr_reader :error_code

      # Whether retrying the operation may succeed.
      # @return [Boolean]
      attr_reader :retry_possible

      # Creates a token error with structured retry information.
      #
      # @param message [String] human-readable failure description
      # @param token_type [String] kind of token associated with the failure
      # @param error_code [String] machine-readable failure code
      # @param retry_possible [Boolean] whether retrying may succeed
      #
      def initialize(message, token_type:, error_code:, retry_possible: false)
        @token_type = token_type
        @error_code = error_code
        @retry_possible = retry_possible
        super(message)
      end
    end

    #
    # Raised for token expiry; its retry metadata permits a refresh/retry.
    #

    class ExpiredTokenError < Error

      # Creates an error describing token expiry.
      # @param token_type [String] kind of token that failed
      #
      def initialize(token_type:)
        super(
          "Token has expired",
          token_type: token_type,
          error_code: 'token_expired',
          retry_possible: true
        )
      end
    end

    #
    # Raised when a token is structurally valid but has been invalidated or revoked
    #

    class InvalidTokenError < Error

      # Creates an error describing token invalidation/revocation.
      # @param token_type [String] kind of token that failed
      #
      def initialize(token_type:)
        super(
          "Token is invalid",
          token_type: token_type,
          error_code: 'token_invalid',
          retry_possible: false
        )
      end
    end

    #
    # Raised during token refresh operations, includes retry information and server responses
    #

    class RefreshError < Error

      # Creates a refresh error with retry metadata.
      #
      # @param message [String] failure description
      # @param retry_possible [Boolean] whether a later retry may succeed
      #
      def initialize(message, retry_possible: true)
        super(
          message,
          token_type: 'refresh',
          error_code: 'refresh_failed',
          retry_possible: retry_possible
        )
      end
    end

    #
    # Handles token refresh operations with retry logic
    #

    class Refresh
      include MonitorMixin

      # Maximum attempts for one refresh operation.
      # @return [Integer]
      MAX_RETRIES = 3

      # Initial retry delay in seconds before jitter.
      # @return [Integer]
      BASE_DELAY = 1

      # Maximum retry delay in seconds before jitter.
      # @return [Integer]
      MAX_DELAY = 8

      # Session containing the tokens to refresh.
      # @return [State::Session]
      attr_reader :session

      # DPoP client used to sign refresh requests.
      # @return [DPoP::Client]
      attr_reader :dpop_client

      # Server providing the token endpoint.
      # @return [Metadata::AuthorizationServer]
      attr_reader :auth_server

      # Client metadata used for optional confidential-client assertions.
      # @return [Metadata::ClientMetadata]
      attr_reader :client_metadata

      # Creates a synchronized refresh operation for an existing OAuth session.
      #
      # @param session [State::Session] session with an access and refresh token
      # @param dpop_client [DPoP::Client] proof signer and nonce tracker
      # @param auth_server [Metadata::AuthorizationServer] server with a token endpoint
      # @param client_metadata [Metadata::ClientMetadata] client ID and authentication key configuration
      # @param signing_key [Hash, JOSE::JWK, nil] private ES256 client-authentication key
      #
      def initialize(session:, dpop_client:, auth_server:, client_metadata:, signing_key: nil)
        super() # Initialize MonitorMixin
        @session = session
        @dpop_client = dpop_client
        @auth_server = auth_server
        @attempt_count = 0
        @client_metadata = client_metadata
        @signing_key = signing_key
      end

      # Exchanges a refresh token for a replacement token set.
      #
      # Retries eligible failures up to {MAX_RETRIES} times with exponential backoff and
      # jitter, and handles a DPoP nonce challenge during token exchange. Does not assign
      # the returned tokens to the session or persist them; the caller must do so.
      #
      # @return [State::TokenSet] validated replacement tokens
      # @raise [RefreshError] if the session is not renewable, refresh fails, or retries are exhausted
      #
      def perform
        synchronize do
          raise RefreshError.new("No refresh token available", retry_possible: false) unless session.renewable?
          raise RefreshError.new("No access token to refresh", retry_possible: false) if session.tokens.nil?

          with_retries do
            request_token_refresh
          end
        end
      end


      private

      def with_retries
        @attempt_count = 0
        last_error = nil

        while @attempt_count < MAX_RETRIES
          begin
            return yield
          rescue RefreshError, HTTPClient::HTTPError => e
            last_error = e
            @attempt_count += 1

            # Don't retry if error indicates retry not possible
            raise e if e.respond_to?(:retry_possible) && !e.retry_possible

            sleep calculate_delay if @attempt_count < MAX_RETRIES
          end
        end

        # Reached max retries
        raise RefreshError.new(
          "Token refresh failed after #{MAX_RETRIES} attempts: #{last_error.message}",
          retry_possible: false
        )
      end

      def calculate_delay
        # Exponential backoff with jitter
        delay = [BASE_DELAY * (2**(@attempt_count - 1)), MAX_DELAY].min
        delay + (rand * 0.5 * delay) # Add up to 50% jitter
      end

      def request_token_refresh
        # Initial token request without nonce
        response = make_token_request(session)

        # Handle DPoP nonce requirement
        if requires_dpop_nonce?(response)
          # Extract and store nonce from error response
          extract_dpop_nonce(response)
          dpop_client.process_response(response[:headers], auth_server.issuer)

          # Retry request with nonce
          response = make_token_request(session)
        end

        handle_refresh_response(response)
      end

      def make_token_request(session)
        # Generate proof
        proof = dpop_client.generate_proof(
          method: 'POST',
          uri: auth_server.token_endpoint
        )

        body = {
          grant_type: 'refresh_token',
          refresh_token: session.tokens.refresh_token,
          scope: session.scope,
          client_id: client_metadata.client_id
        }

        # Add client authentication if available
        add_client_authentication(body) if client_metadata.confidential?

        AuthProto.configuration.http_client.post(
          auth_server.token_endpoint,
          body: body,
          headers: {
            "Content-Type" => "application/x-www-form-urlencoded",
            "DPoP" => proof
          }
        )
      end

      def requires_dpop_nonce?(response)
        return false unless response[:status] == 400
        return false if response[:body].nil?

        error_data = JSON.parse(response[:body])
        error_data.is_a?(Hash) && error_data['error'] == DPoP::ERROR_USE_NONCE
      rescue JSON::ParserError
        false
      end

      def extract_dpop_nonce(response)
        nonce = (response[:headers] || {}).detect { |k, v| k.downcase == 'dpop-nonce' }&.last

        unless nonce.is_a?(String) && !nonce.empty?
          raise RefreshError.new("No DPoP nonce provided in error response", retry_possible: false)
        end

        nonce
      end

      def add_client_authentication(body)
        client_assertion = PAR::ClientAssertion.new(
          client_id: client_metadata.client_id,
          signing_key: @signing_key
        )

        body.merge!(
          client_assertion_type: PAR::CLIENT_ASSERTION_TYPE,
          client_assertion: client_assertion.generate_jwt(
            audience: auth_server.issuer
          )
        )
      end

      def handle_refresh_response(response)
        case response[:status]
        when 200
          process_successful_response(response)
        when 400
          handle_400_response(response)
        when 401
          raise RefreshError.new("Refresh token is invalid", retry_possible: false)
        when 429
          handle_rate_limit_response(response)
        else
          raise RefreshError, "Unexpected response: #{response[:status]}"
        end
      end

      def process_successful_response(response)
        raise RefreshError.new("Missing response body", retry_possible: false) if response[:body].nil?

        data = JSON.parse(response[:body])
        validate_refresh_response(data)

        AuthProto::State::TokenSet.new(
          access_token: data['access_token'],
          token_type: data['token_type'],
          expires_in: data['expires_in'],
          refresh_token: data['refresh_token'],
          scope: data['scope'],
          sub: data['sub']
        )
      rescue JSON::ParserError => e
        raise RefreshError.new("Invalid response format: #{e.message}", retry_possible: false)
      end

      def handle_400_response(response)
        raise RefreshError.new("Missing error response body", retry_possible: false) if response[:body].nil?

        error_data = JSON.parse(response[:body])

        unless error_data.is_a?(Hash)
          raise RefreshError.new("Invalid error response format", retry_possible: false)
        end

        error_description = error_data['error_description'] || error_data['error']

        case error_data['error']
        when DPoP::ERROR_USE_NONCE
          extract_dpop_nonce(response)
          dpop_client.process_response(response[:headers], auth_server.issuer)
          raise RefreshError.new("Retry with DPoP nonce", retry_possible: true)
        when "invalid_grant"
          # The refresh token has been invalidated or already used
          raise RefreshError.new(
            "Refresh token has been invalidated: #{error_description}",
            retry_possible: false
          )
        else
          raise RefreshError.new(
            "Refresh request failed: #{error_description}",
            retry_possible: false
          )
        end
      rescue JSON::ParserError
        raise RefreshError.new("Invalid error response format", retry_possible: false)
      end

      def handle_rate_limit_response(response)
        # Extract retry-after if available
        retry_after = response[:headers]["Retry-After"]&.to_i || calculate_delay
        raise RefreshError, "Rate limited - retry after #{retry_after} seconds"
      end

      def validate_refresh_response(data)
        unless data.is_a?(Hash)
          raise RefreshError.new("Token response must be a JSON object", retry_possible: false)
        end

        # Required fields
        %w[access_token token_type expires_in scope sub].each do |field|
          raise RefreshError.new("Missing #{field} in response", retry_possible: false) unless data[field]
        end

        %w[access_token token_type scope sub].each do |field|
          unless data[field].is_a?(String) && !data[field].empty?
            raise RefreshError.new("Invalid #{field} in response", retry_possible: false)
          end
        end

        unless data['expires_in'].is_a?(Integer)
          raise RefreshError.new("Invalid expires_in in response", retry_possible: false)
        end

        unless data['refresh_token'].nil? || data['refresh_token'].is_a?(String)
          raise RefreshError.new("Invalid refresh_token in response", retry_possible: false)
        end

        # Token type must be DPoP
        unless data['token_type'] == 'DPoP'
          raise RefreshError.new("Invalid token_type: #{data['token_type']}", retry_possible: false)
        end

        # Scope must include original scopes
        original_scopes = session.scope.split
        response_scopes = data['scope'].split
        unless (original_scopes - response_scopes).empty?
          raise RefreshError.new("Invalid scope in response", retry_possible: false)
        end

        # Subject must match
        return if data['sub'] == session.tokens.sub

        raise RefreshError.new("Subject mismatch in response", retry_possible: false)
      end
    end
  end
end
