# frozen_string_literal: true

require_relative '../client_assertion'
require_relative '../configuration'
require_relative '../errors'
require_relative '../http_helpers'

module AuthProto
  module Token

    #
    # Revokes tokens using the issuing server and the session's authentication keys.
    #

    class Revocation
      include HTTPHelpers

      # Error raised when revocation is unavailable or rejected by the server.
      class Error < AuthProto::Error; end

      # Creates a revoker using the original session's server and authentication keys.
      #
      # @param session [State::Session] session bound to the issuing authorization server
      # @param dpop_client [DPoP::Client] proof signer and nonce tracker
      # @param client_metadata [Metadata::ClientMetadata] client authentication configuration
      # @param client_assertion [ClientAssertion, nil] confidential-client assertion signer
      #
      def initialize(session:, dpop_client:, client_metadata:, client_assertion: nil)
        @session = session
        @dpop_client = dpop_client
        @client_metadata = client_metadata
        @client_assertion = client_assertion
      end

      # Revokes an access or refresh token and requires a successful response.
      # The response body is ignored, including for tokens already revoked.
      #
      # @param token [String] nonempty token to revoke
      # @param token_type [String, Symbol] `access_token` or `refresh_token`
      # @return [void]
      # @raise [ArgumentError] if the token or hint is invalid
      # @raise [Error] if the endpoint is absent or the server rejects revocation
      # @raise [DPoP::Client::Error, HTTPClient::HTTPError] if proof or transport handling fails
      #
      def revoke_token(token, token_type:)
        raise ArgumentError, "Token must be a nonempty string" unless token.is_a?(String) && !token.empty?

        token_type = token_type.to_s if token_type.is_a?(Symbol)

        unless %w[access_token refresh_token].include?(token_type)
          raise ArgumentError, "Invalid token_type"
        end

        endpoint = @session.auth_server&.revocation_endpoint
        raise Error, "Authorization server does not advertise a revocation endpoint" unless endpoint

        response = @dpop_client.with_nonce_handling(@session.session_id, endpoint) do
          make_request(token, endpoint, token_type)
        end

        raise Error, "Token revocation failed: HTTP #{response[:status]}" unless response_status(response) == 200
      end


      private

      def make_request(token, endpoint, token_type)
        body = {
          token: token,
          token_type_hint: token_type,
          client_id: @client_metadata.client_id
        }

        if @client_metadata.confidential?
          body.merge!(
            client_assertion_type: ClientAssertion::TYPE,
            client_assertion: @client_assertion.generate_jwt(audience: @session.auth_server.issuer)
          )
        end

        proof = @dpop_client.generate_proof(session: @session, method: 'POST', uri: endpoint)

        AuthProto.configuration.http_client.post(
          endpoint,
          body: body,
          headers: {
            'Content-Type' => 'application/x-www-form-urlencoded',
            'DPoP' => proof
          }
        )
      end
    end
  end
end
