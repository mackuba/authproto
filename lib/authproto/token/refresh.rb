# frozen_string_literal: true

require 'jose'
require 'json'
require 'monitor'

require_relative '../configuration'
require_relative '../errors'
require_relative '../http_client'
require_relative '../http_helpers'
require_relative '../par'
require_relative '../par/client_assertion'
require_relative '../state/token_set'
require_relative 'identity'
require_relative 'response'
require_relative 'revocation'

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
      include HTTPHelpers
      include Identity
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
      # @param client_assertion [PAR::ClientAssertion, nil] reusable validated signer; required for confidential clients
      # @raise [ArgumentError] if confidential-client metadata is supplied without an assertion signer
      #
      def initialize(session:, dpop_client:, auth_server:, client_metadata:, client_assertion: nil)
        super() # Initialize MonitorMixin

        @session = session
        @dpop_client = dpop_client
        @auth_server = auth_server
        @attempt_count = 0
        @client_metadata = client_metadata
        @client_assertion = client_assertion

        if client_metadata.confidential? && !client_assertion.is_a?(PAR::ClientAssertion)
          raise ArgumentError, "Confidential clients require a client_assertion signer"
        end
      end

      # Exchanges a refresh token for a replacement token set.
      #
      # Makes up to {MAX_RETRIES} attempts for eligible failures, with exponential backoff
      # and jitter. Each attempt can retry one DPoP nonce challenge. Does not assign
      # the returned tokens to the session or persist them; the caller must do so.
      # HTTP 400/401 OAuth errors preserve the server's error code and description in the exception message.
      # Retains the existing refresh token when the response omits a replacement.
      # Verifies the subject's current PDS before the exchange and attempts revocation on identity mismatch.
      #
      # @return [State::TokenSet] validated replacement tokens
      # @raise [RefreshError] if the session is not renewable, refresh fails, or retries are exhausted
      # @raise [DPoP::Client::Error] if any response lacks a valid nonce or nonce persistence fails
      #
      def perform_refresh
        synchronize do
          raise RefreshError.new("No refresh token available", retry_possible: false) unless session.renewable?
          raise RefreshError.new("No access token to refresh", retry_possible: false) if session.tokens.nil?

          validate_identity

          with_retries do
            request_token_refresh
          end
        end
      end


      private

      def validate_identity
        validate_subject_pds(session.did, session)
      rescue IdentityError => e
        revoke_rejected_refresh_token(session.tokens.refresh_token) if session.tokens.refresh_token
        raise RefreshError.new(e.message, retry_possible: false)
      end

      def revoke_rejected_refresh_token(token)
        return unless session.can_be_revoked?

        revocation = Revocation.new(
          session: session,
          dpop_client: dpop_client,
          client_metadata: client_metadata,
          client_assertion: @client_assertion
        )

        revocation.revoke_token(token, :token_type => :refresh_token)
      rescue StandardError
        # Cleanup failures must not replace the original identity error.
        nil
      end

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
        response = dpop_client.with_nonce_handling(session, auth_server.token_endpoint) do
          make_token_request(session)
        end

        handle_refresh_response(response)
      end

      def make_token_request(session)
        dpop_proof = dpop_client.generate_proof(session: session, method: 'POST', uri: auth_server.token_endpoint)

        body = {
          grant_type: 'refresh_token',
          refresh_token: session.tokens.refresh_token,
          client_id: client_metadata.client_id
        }

        add_client_authentication(body) if client_metadata.confidential?

        AuthProto.configuration.http_client.post(
          auth_server.token_endpoint,
          body: body,
          headers: {
            "Content-Type" => "application/x-www-form-urlencoded",
            "DPoP" => dpop_proof
          }
        )
      end

      def add_client_authentication(body)
        body.merge!(
          client_assertion_type: PAR::CLIENT_ASSERTION_TYPE,
          client_assertion: @client_assertion.generate_jwt(audience: auth_server.issuer)
        )
      end

      def handle_refresh_response(response)
        case response[:status]
        when 200
          process_successful_response(response)
        when 400, 401
          handle_error_response(response)
        when 429
          handle_rate_limit_response(response)
        else
          raise RefreshError, "Unexpected response: #{response[:status]}"
        end
      end

      def process_successful_response(response)
        tokens = Response.parse(response, current_tokens: session.tokens)
        validate_refresh_identity(tokens)
        tokens
      rescue Response::Error => e
        raise RefreshError.new(e.message, retry_possible: false)
      end

      def handle_error_response(response)
        raise RefreshError.new("Missing error response body", retry_possible: false) if response[:body].nil?

        error_data = JSON.parse(response[:body])

        unless error_data.is_a?(Hash)
          raise RefreshError.new("Invalid error response format", retry_possible: false)
        end

        error_description = [error_data['error'], error_data['error_description']].compact.join(': ')

        case error_data['error']
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
        retry_after = response_header(response, 'Retry-After')
        retry_after = retry_after&.to_i || calculate_delay
        raise RefreshError, "Rate limited - retry after #{retry_after} seconds"
      end

      def validate_refresh_identity(tokens)
        if tokens.sub != session.tokens.sub
          revoke_rejected_refresh_token(tokens.refresh_token) if tokens.refresh_token
          raise RefreshError.new("Subject mismatch in response", retry_possible: false)
        end
      end
    end
  end
end
