# frozen_string_literal: true

require 'json'
require 'uri'

require_relative '../configuration'
require_relative '../errors'
require_relative '../http_client'
require_relative '../metadata'
require_relative '../validated_uri'

module AuthProto
  module Metadata

    #
    # Handles fetching and validation of AT Protocol OAuth Authorization Server metadata.
    # An Authorization Server in atproto can be either a PDS instance or a separate "entryway" server
    # that handles authentication for multiple PDS instances.
    #
    # The Authorization Server metadata is fetched from the well-known endpoint
    # /.well-known/oauth-authorization-server and must conform to RFC 8414 plus additional
    # requirements specific to the AT Protocol OAuth profile.
    #
    # @example Fetching and validating Authorization Server metadata
    #   begin
    #     auth_server = AuthProto::Metadata::AuthorizationServer.from_issuer("https://auth.example.com")
    #     puts "Authorization endpoint: #{auth_server.authorization_endpoint}"
    #     puts "Supported scopes: #{auth_server.scopes_supported}"
    #   rescue AuthProto::InvalidAuthorizationServer => e
    #     puts "Failed to validate authorization server: #{e.message}"
    #   end
    #
    # @see https://atproto.com/specs/oauth#authorization-servers Documentation of Authorization Server requirements
    #

    class AuthorizationServer

      # Metadata keys that must be present before capability validation.
      # @return [Array<String>]
      REQUIRED_FIELDS = %w[
        issuer
        authorization_endpoint
        token_endpoint
        response_types_supported
        grant_types_supported
        code_challenge_methods_supported
        token_endpoint_auth_methods_supported
        token_endpoint_auth_signing_alg_values_supported
        scopes_supported
        dpop_signing_alg_values_supported
        pushed_authorization_request_endpoint
      ].freeze

      # Authorization server issuer origin.
      # @return [String]
      attr_reader :issuer

      # HTTPS browser authorization endpoint.
      # @return [String]
      attr_reader :authorization_endpoint

      # HTTPS token exchange and refresh endpoint.
      # @return [String]
      attr_reader :token_endpoint

      # HTTPS PAR endpoint.
      # @return [String]
      attr_reader :pushed_authorization_request_endpoint

      # Supported response types, including `code`.
      # @return [Array<String>]
      attr_reader :response_types_supported

      # Supported grant types, including authorization code and refresh token.
      # @return [Array<String>]
      attr_reader :grant_types_supported

      # Supported PKCE methods, including `S256`.
      # @return [Array<String>]
      attr_reader :code_challenge_methods_supported

      # Supported client authentication methods.
      # @return [Array<String>]
      attr_reader :token_endpoint_auth_methods_supported

      # Supported client assertion algorithms.
      # @return [Array<String>]
      attr_reader :token_endpoint_auth_signing_alg_values_supported

      # Supported scopes, including `atproto`.
      # @return [Array<String>]
      attr_reader :scopes_supported

      # Supported DPoP algorithms, including `ES256`.
      # @return [Array<String>]
      attr_reader :dpop_signing_alg_values_supported

      # Validates an authorization server's OAuth metadata.
      #
      # @param metadata [Hash{String => Object}] parsed discovery document with the fields in {REQUIRED_FIELDS} and required Boolean capabilities
      # @raise [InvalidAuthorizationServer] if required capabilities, issuer or endpoint schemes are invalid
      # @raise [URI::InvalidURIError] if a metadata URL cannot be parsed
      #
      def initialize(metadata)
        validate_and_set_metadata(metadata)
      end

      # Fetches `/.well-known/oauth-authorization-server` using the configured transport.
      # Requires HTTP 200 without redirects and a JSON object served as application/json.
      #
      # The document's issuer must exactly match the requested issuer.
      #
      # @param issuer [String] authorization server issuer origin
      # @return [AuthorizationServer] validated discovery metadata
      # @raise [InvalidAuthorizationServer] if HTTP transport fails, JSON is invalid, or metadata/issuer validation fails
      # @raise [HTTPClient::SSRFError] if the transport rejects the initial destination
      # @raise [URI::InvalidURIError] if the issuer or a metadata URI cannot be parsed
      #
      def self.from_issuer(issuer)
        validate_source_url(issuer)

        response = fetch_metadata(issuer)
        validate_response(response)

        metadata = parse_metadata(response[:body])
        validate_issuer(metadata["issuer"], issuer)
        new(metadata)
      end

      # Exports metadata for serialization using symbol keys.
      #
      # Includes issuer/endpoints (String), capability lists (Array<String>), and the
      # three required Boolean flags set to `true`. Use JSON serialization to obtain
      # string keys suitable for passing back to {#initialize}.
      #
      # @return [Hash{Symbol => String, Array<String>, Boolean}] authorization server metadata
      #
      def to_h
        {
          issuer: issuer,
          authorization_endpoint: authorization_endpoint,
          token_endpoint: token_endpoint,
          pushed_authorization_request_endpoint: pushed_authorization_request_endpoint,
          response_types_supported: response_types_supported,
          grant_types_supported: grant_types_supported,
          code_challenge_methods_supported: code_challenge_methods_supported,
          token_endpoint_auth_methods_supported: token_endpoint_auth_methods_supported,
          token_endpoint_auth_signing_alg_values_supported: token_endpoint_auth_signing_alg_values_supported,
          scopes_supported: scopes_supported,
          dpop_signing_alg_values_supported: dpop_signing_alg_values_supported,
          authorization_response_iss_parameter_supported: true,
          require_pushed_authorization_requests: true,
          client_id_metadata_document_supported: true
        }
      end

      private

      def validate_and_set_metadata(metadata)
        REQUIRED_FIELDS.each do |field|
          raise InvalidAuthorizationServer, "#{field} is required" unless metadata[field]
        end

        @issuer = validate_issuer(metadata["issuer"])
        @authorization_endpoint = validate_https_url(metadata["authorization_endpoint"])
        @token_endpoint = validate_https_url(metadata["token_endpoint"])
        @pushed_authorization_request_endpoint = validate_https_url(metadata["pushed_authorization_request_endpoint"])

        validate_response_types(metadata["response_types_supported"])
        validate_grant_types(metadata["grant_types_supported"])
        validate_code_challenge_methods(metadata["code_challenge_methods_supported"])
        validate_token_endpoint_auth_methods(metadata["token_endpoint_auth_methods_supported"])
        validate_token_endpoint_auth_signing_algs(metadata["token_endpoint_auth_signing_alg_values_supported"])
        validate_dpop_signing_algs(metadata["dpop_signing_alg_values_supported"])
        validate_scopes(metadata["scopes_supported"])

        # Store validated values
        @response_types_supported = metadata["response_types_supported"]
        @grant_types_supported = metadata["grant_types_supported"]
        @code_challenge_methods_supported = metadata["code_challenge_methods_supported"]
        @token_endpoint_auth_methods_supported = metadata["token_endpoint_auth_methods_supported"]
        @token_endpoint_auth_signing_alg_values_supported = metadata["token_endpoint_auth_signing_alg_values_supported"]
        @scopes_supported = metadata["scopes_supported"]
        @dpop_signing_alg_values_supported = metadata["dpop_signing_alg_values_supported"]

        # Required boolean fields
        validate_boolean_field(metadata, "authorization_response_iss_parameter_supported", true)
        validate_boolean_field(metadata, "require_pushed_authorization_requests", true)
        validate_boolean_field(metadata, "client_id_metadata_document_supported", true)
      end

      def validate_issuer(issuer)
        uri = ValidatedURI.new(issuer)

        is_valid = (
          uri.scheme == 'https' && (!uri.specified_port || uri.effective_port != 443) &&
          uri.path.empty? && !uri.query && !uri.fragment && !uri.userinfo
        )

        raise InvalidAuthorizationServer, "invalid issuer URL format" unless is_valid

        issuer
      end

      def validate_https_url(url)
        uri = ValidatedURI.new(url)
        raise InvalidAuthorizationServer, "URL must use HTTPS" unless uri.scheme == "https"

        url
      end

      def validate_response_types(types)
        raise InvalidAuthorizationServer, "must support 'code' response type" unless types.include?("code")
      end

      def validate_grant_types(types)
        required = %w[authorization_code refresh_token]
        missing = required - types
        raise InvalidAuthorizationServer, "missing grant types: #{missing.join(", ")}" if missing.any?
      end

      def validate_code_challenge_methods(methods)
        raise InvalidAuthorizationServer, "must support S256 PKCE" unless methods.include?("S256")
      end

      def validate_token_endpoint_auth_methods(methods)
        required = %w[private_key_jwt none]
        missing = required - methods
        raise InvalidAuthorizationServer, "missing auth methods: #{missing.join(", ")}" if missing.any?
      end

      def validate_token_endpoint_auth_signing_algs(algs)
        raise InvalidAuthorizationServer, "must support ES256" unless algs.include?("ES256")
        raise InvalidAuthorizationServer, "must not allow 'none'" if algs.include?("none")
      end

      def validate_dpop_signing_algs(algs)
        raise InvalidAuthorizationServer, "must support ES256 for DPoP" unless algs.include?("ES256")
      end

      def validate_scopes(scopes)
        required = %w[atproto]
        missing = required - scopes
        raise InvalidAuthorizationServer, "missing scopes: #{missing.join(", ")}" if missing.any?
      end

      def validate_boolean_field(metadata, field, required_value)
        actual = metadata[field]
        return if actual == required_value

        raise InvalidAuthorizationServer, "#{field} must be #{required_value}"
      end

      class << self
        private

        def validate_source_url(issuer)
          uri = ValidatedURI.new(issuer)

          valid = (
            uri.scheme == 'https' && (!uri.specified_port || uri.effective_port != 443) &&
            uri.path.empty? && !uri.userinfo && !uri.query && !uri.fragment
          )

          raise InvalidAuthorizationServer, "Invalid authorization server issuer URL" unless valid
        rescue URI::InvalidURIError => e
          raise InvalidAuthorizationServer, "Invalid authorization server issuer URL: #{e.message}"
        end

        def fetch_metadata(issuer)
          metadata_url = URI.join(issuer, "/.well-known/oauth-authorization-server")
          AuthProto.configuration.http_client.get(metadata_url.to_s, follow_redirects: false)
        rescue HTTPClient::HTTPError => e
          raise InvalidAuthorizationServer, "Failed to fetch authorization server metadata: #{e.message}"
        end

        def validate_response(response)
          unless response[:status] == 200
            raise InvalidAuthorizationServer, "Authorization server metadata must return HTTP 200"
          end

          content_type = response[:headers]["content-type"].to_s.split(";", 2).first.to_s.strip

          unless content_type.casecmp?('application/json')
            raise InvalidAuthorizationServer, "Authorization server metadata must use application/json"
          end
        end

        def parse_metadata(body)
          metadata = JSON.parse(body.to_s)

          unless metadata.is_a?(Hash)
            raise InvalidAuthorizationServer, "Authorization server metadata must be a JSON object"
          end

          metadata
        rescue JSON::ParserError => e
          raise InvalidAuthorizationServer, "Invalid JSON in authorization server metadata: #{e.message}"
        end

        def validate_issuer(metadata_issuer, request_issuer)
          return if metadata_issuer == request_issuer

          raise InvalidAuthorizationServer, "issuer mismatch: #{metadata_issuer} != #{request_issuer}"
        end
      end
    end
  end
end
