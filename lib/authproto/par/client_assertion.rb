# frozen_string_literal: true

require 'securerandom'

module AuthProto
  module PAR

    #
    # Generates client authentication JWTs according to RFC 7523 for AT Protocol OAuth.
    # Creates signed assertions using ES256 with required claims including iss/sub (client_id),
    # aud (authorization server issuer), jti (unique ID), and iat/exp (timing claims).
    #

    class ClientAssertion

      # Raised when client assertion key import or JWT signing fails.
      class Error < AuthProto::Error; end

      # Creates an ES256 client assertion signer.
      #
      # @param client_id [String] client ID used in `iss` and `sub`
      # @param signing_key [JOSE::JWK] private EC P-256 signing key, including its `kid`
      #
      def initialize(client_id:, signing_key:)
        @client_id = client_id
        @signing_key = signing_key
      end

      # Signs a short-lived client authentication JWT with ES256.
      #
      # Includes `iss`, `sub`, `aud`, a unique `jti`, and `iat`/`exp` times.
      #
      # @param audience [String] authorization server issuer URL used as the assertion audience
      # @param lifetime [Integer] validity in seconds; defaults to five minutes
      # @return [String] compact signed client assertion JWT
      # @raise [Error] if JWK import or JWT signing fails
      #
      def generate_jwt(audience:, lifetime: 300)
        now = Time.now.to_i

        payload = {
          # Required claims
          iss: @client_id, # Issuer is client_id
          sub: @client_id, # Subject is client_id
          aud: audience, # Audience is the authorization server issuer
          jti: SecureRandom.uuid, # Unique identifier
          exp: now + lifetime, # Expiration time
          iat: now # Issued at time
        }

        # Header specifying ES256 algorithm for signing
        header = {
          alg: "ES256",
          typ: "JWT",
          kid: @signing_key.fields["kid"]
        }

        # Sign and return the JWT
        key = JWT::JWK.import(@signing_key.to_map.to_h)
        JWT.encode(payload, key, "ES256", header)
      rescue JWT::Error, ArgumentError => e
        raise Error, "Failed to generate client assertion: #{e.message}"
      end
    end
  end
end
