# frozen_string_literal: true

require_relative '../configuration'
require_relative '../par'

module AuthProto
  module Token

    #
    # Best-effort revocation of refresh tokens rejected during identity validation.
    #

    class Revocation

      # Creates a revoker using the original session's server and authentication keys.
      #
      # @param session [State::Session] session bound to the issuing authorization server
      # @param dpop_client [DPoP::Client] proof signer and nonce tracker
      # @param client_metadata [Metadata::ClientMetadata] client authentication configuration
      # @param client_assertion [PAR::ClientAssertion, nil] confidential-client assertion signer
      #
      def initialize(session:, dpop_client:, client_metadata:, client_assertion: nil)
        @session = session
        @dpop_client = dpop_client
        @client_metadata = client_metadata
        @client_assertion = client_assertion
      end

      # Attempts revocation when a refresh token and advertised endpoint are available.
      # Failures are ignored so they cannot replace the original identity error.
      #
      # @param token [String, nil] refresh token to revoke
      # @return [void]
      #
      def revoke_refresh_token(token)
        return unless token.is_a?(String) && !token.empty?

        endpoint = @session.auth_server&.revocation_endpoint
        return unless endpoint

        @dpop_client.with_nonce_handling(@session, endpoint) do
          make_request(token, endpoint)
        end

        nil
      rescue StandardError
        nil
      end


      private

      def make_request(token, endpoint)
        body = {
          token: token,
          token_type_hint: 'refresh_token',
          client_id: @client_metadata.client_id
        }

        if @client_metadata.confidential?
          body.merge!(
            client_assertion_type: PAR::CLIENT_ASSERTION_TYPE,
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
