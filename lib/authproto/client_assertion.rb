# frozen_string_literal: true

require 'jose'
require 'jwt'
require 'securerandom'

require_relative 'configuration'
require_relative 'errors'

module AuthProto

  #
  # @api private
  #
  # Generates client authentication JWTs according to RFC 7523 for AT Protocol OAuth.
  # Creates signed assertions using ES256 with required claims including iss/sub (client_id),
  # aud (authorization server issuer), jti (unique ID), and iat/exp (timing claims).
  #

  class ClientAssertion

    # Raised when client assertion key import or JWT signing fails.
    class Error < AuthProto::Error; end

    # JWS signing algorithm used for client assertions.
    # @return [String]
    ALGORITHM = "ES256"

    # URN identifying the assertion type, set in the `client_assertion_type` field in OAuth requests.
    # @return [String]
    TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

    # Validated private EC P-256 key used by this reusable assertion signer.
    # @return [JOSE::JWK]
    attr_reader :signing_key

    # Creates an ES256 client assertion signer.
    #
    # @param client_id [String] client ID used in `iss` and `sub`
    # @param signing_key [Hash, JOSE::JWK] private EC P-256 signing key, including its `kid`
    # @raise [Error] if the key cannot sign with ES256 or its usage is incompatible
    #   (`key_ops`, when present, must contain `sign` and optionally `verify`, without duplicates)
    # @raise [Error] if the client ID is not a nonblank string
    #
    def initialize(client_id:, signing_key:)
      unless client_id.is_a?(String) && !client_id.strip.empty?
        raise Error, "client_id must be a nonblank string"
      end

      @client_id = client_id.dup.freeze
      @signing_key = validate_signing_key(signing_key)
    rescue ClientAssertion::Error
      raise
    rescue StandardError => e
      raise Error, "Invalid signing_key: #{e.message}"
    end

    # Signs a fresh, short-lived client authentication JWT with the cached ES256 key.
    #
    # Includes `iss`, `sub`, `aud`, a unique `jti`, and `iat`/`exp` times.
    #
    # @param audience [String] authorization server issuer URL used as the assertion audience
    # @param lifetime [Integer] positive validity in seconds; defaults to {Configuration#client_assertion_lifetime}
    # @return [String] compact signed client assertion JWT
    # @raise [Error] if the audience is not a nonblank string, lifetime is not a positive integer, or signing fails
    #
    def generate_jwt(audience:, lifetime: AuthProto.configuration.client_assertion_lifetime)
      unless audience.is_a?(String) && !audience.strip.empty?
        raise Error, "audience must be a nonblank string"
      end

      unless lifetime.is_a?(Integer) && lifetime.positive?
        raise Error, "lifetime must be a positive integer"
      end

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
        alg: ALGORITHM,
        typ: 'JWT',
        kid: @signing_key.fields['kid']
      }

      JWT.encode(payload, @jwt_signing_key, ALGORITHM, header)
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

      if (data.key?('alg') && data['alg'] != ALGORITHM) ||
         (data.key?('use') && data['use'] != 'sig')
        raise Error, "signing_key must be active and permit #{ALGORITHM} signing"
      end

      if data.key?('key_ops')
        raise Error, "signing_key.key_ops is not an array" unless data['key_ops'].is_a?(Array)

        ops = data['key_ops'].sort_by(&:to_s)

        unless ops == ['sign'] || ops == ['sign', 'verify']
          raise Error, "signing_key.key_ops must contain sign and optionally verify, without duplicates"
        end
      end

      signing_key = JOSE::JWK.from_map(data)

      imported_key = JWT::JWK.import(data)
      proof = JWT.encode({}, imported_key, ALGORITHM)
      JWT.decode(proof, imported_key.public_key, true, algorithms: [ALGORITHM])

      @jwt_signing_key = imported_key

      signing_key
    end
  end
end
