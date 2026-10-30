# frozen_string_literal: true

require 'jwt'
require 'jose'
require 'securerandom'

require_relative '../errors'

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

      attr_reader :signing_key

      # Creates an ES256 client assertion signer.
      #
      # @param client_id [String] client ID used in `iss` and `sub`
      # @param signing_key [Hash, JOSE::JWK] private EC P-256 signing key, including its `kid`
      # @raise [Error] if the key cannot sign with ES256 or its usage is incompatible
      #
      def initialize(client_id:, signing_key:)
        @client_id = client_id
        @signing_key = validate_signing_key(signing_key)
      rescue ClientAssertion::Error
        raise
      rescue StandardError => e
        raise Error, "Invalid signing_key: #{e.message}"
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
          iss: @client_id,        # issuer
          sub: @client_id,        # subject
          aud: audience,          # audience is the authorization server issuer
          jti: SecureRandom.uuid, # token identifier
          exp: now + lifetime,    # expiration time
          iat: now                # issued at time
        }

        header = {
          alg: 'ES256',
          typ: 'JWT',
          kid: @signing_key.fields['kid']
        }

        key = JWT::JWK.import(@signing_key.to_map.to_h)
        JWT.encode(payload, key, 'ES256', header)
      rescue JWT::Error, ArgumentError => e
        raise Error, "Failed to generate client assertion: #{e.message}"
      end


      private

      def validate_signing_key(signing_key)
        data = signing_key.is_a?(JOSE::JWK) ? signing_key.to_map.to_h : signing_key

        raise Error, "signing_key must be a hash or a JOSE::JWK" unless data.is_a?(Hash)
        raise Error, "signing_key must be active" if data['revoked']

        unless data['kty'] == 'EC' && data['crv'] == 'P-256'
          raise Error, "signing_key must be a EC P-256 JWK"
        end

        unless data['d'].is_a?(String) && !data['d'].empty?
          raise Error, "signing_key must be a private key ('d' field must not be empty)"
        end

        %w[kid x y].each do |field|
          unless data[field].is_a?(String) && !data[field].empty?
            raise Error, "signing_key '#{field}' field must not be empty"
          end
        end

        if (data.key?('alg') && data['alg'] != 'ES256') ||
           (data.key?('use') && data['use'] != 'sig') ||
           (data.key?('key_ops') && (!data['key_ops'].is_a?(Array) || !data['key_ops'].include?('sign')))
          raise Error, "signing_key must be active and permit ES256 signing"
        end

        signing_key = JOSE::JWK.from_map(data)

        imported = JWT::JWK.import(data)
        proof = JWT.encode({}, imported, 'ES256')
        JWT.decode(proof, imported.public_key, true, algorithms: ['ES256'])

        signing_key
      end
    end
  end
end
