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
        authorization_response_iss_parameter_supported
        require_pushed_authorization_requests
        pushed_authorization_request_endpoint
        dpop_signing_alg_values_supported
        client_id_metadata_document_supported
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
        validate_issuer_matches(metadata['issuer'], issuer)

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

      def validate_and_set_metadata(data)
        REQUIRED_FIELDS.each do |field|
          raise InvalidAuthorizationServer, "#{field} is required" unless data[field]
        end

        @issuer = validate_issuer(data['issuer'])

        # Endpoint strings
        @authorization_endpoint = validate_https_url(data['authorization_endpoint'])
        @token_endpoint = validate_https_url(data['token_endpoint'])
        @pushed_authorization_request_endpoint = validate_https_url(data['pushed_authorization_request_endpoint'])

        # Capability lists
        @response_types_supported = data['response_types_supported']
        @grant_types_supported = data['grant_types_supported']
        @code_challenge_methods_supported = data['code_challenge_methods_supported']
        @token_endpoint_auth_methods_supported = data['token_endpoint_auth_methods_supported']
        @token_endpoint_auth_signing_alg_values_supported = data['token_endpoint_auth_signing_alg_values_supported']
        @scopes_supported = data['scopes_supported']
        @dpop_signing_alg_values_supported = data['dpop_signing_alg_values_supported']

        validate_response_types
        validate_grant_types
        validate_code_challenge_methods
        validate_token_endpoint_auth_methods
        validate_token_endpoint_auth_signing_algs
        validate_dpop_signing_algs
        validate_scopes

        # Required boolean fields
        validate_boolean_field(data, 'authorization_response_iss_parameter_supported', true)
        validate_boolean_field(data, 'require_pushed_authorization_requests', true)
        validate_boolean_field(data, 'client_id_metadata_document_supported', true)

        if data.key?('require_request_uri_registration')
          validate_boolean_field(data, 'require_request_uri_registration', true)
        end
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
        raise InvalidAuthorizationServer, "URL must use HTTPS" unless uri.scheme == 'https'
        raise InvalidAuthorizationServer, "Endpoint URL must not contain a fragment" if uri.fragment

        url
      end

      def validate_response_types
        validate_string_array(@response_types_supported, 'response_types_supported')

        unless @response_types_supported.include?('code')
          raise InvalidAuthorizationServer, "response_types_supported must include 'code'"
        end
      end

      def validate_grant_types
        validate_string_array(@grant_types_supported, 'grant_types_supported')

        unless %w[authorization_code refresh_token] - @grant_types_supported == []
          raise InvalidAuthorizationServer, "grant types should include 'authorization_code' and 'refresh_token'"
        end
      end

      def validate_code_challenge_methods
        validate_string_array(@code_challenge_methods_supported, 'code_challenge_methods_supported')

        unless @code_challenge_methods_supported.include?('S256')
          raise InvalidAuthorizationServer, "code_challenge_methods_supported must include S256"
        end
      end

      def validate_token_endpoint_auth_methods
        validate_string_array(@token_endpoint_auth_methods_supported, 'token_endpoint_auth_methods_supported')

        unless %w[private_key_jwt none] - @token_endpoint_auth_methods_supported == []
          raise InvalidAuthorizationServer, "auth methods must include 'private_key_jwt' and 'none'"
        end
      end

      def validate_token_endpoint_auth_signing_algs
        validate_string_array(
          @token_endpoint_auth_signing_alg_values_supported, 'token_endpoint_auth_signing_alg_values_supported'
        )

        unless @token_endpoint_auth_signing_alg_values_supported.include?('ES256')
          raise InvalidAuthorizationServer, "token_endpoint_auth_signing_alg_values_supported must include ES256"
        end

        if @token_endpoint_auth_signing_alg_values_supported.include?('none')
          raise InvalidAuthorizationServer, "token_endpoint_auth_signing_alg_values_supported must not include 'none'"
        end
      end

      def validate_dpop_signing_algs
        validate_string_array(@dpop_signing_alg_values_supported, 'dpop_signing_alg_values_supported')

        unless @dpop_signing_alg_values_supported.include?('ES256')
          raise InvalidAuthorizationServer, "dpop_signing_alg_values_supported must include ES256"
        end
      end

      def validate_scopes
        validate_string_array(@scopes_supported, 'scopes_supported')

        unless @scopes_supported.include?('atproto')
          raise InvalidAuthorizationServer, "scopes_supported must include 'atproto'"
        end
      end

      def validate_string_array(values, field)
        unless values.is_a?(Array)
          raise InvalidAuthorizationServer, "#{field} must be an array"
        end

        unless values.all? { |value| value.is_a?(String) }
          raise InvalidAuthorizationServer, "#{field} must contain only strings"
        end
      end

      def validate_boolean_field(metadata, field, required_value)
        unless metadata[field] == required_value
          raise InvalidAuthorizationServer, "#{field} must be #{required_value}"
        end
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

        def validate_issuer_matches(metadata_issuer, request_issuer)
          return if metadata_issuer == request_issuer

          raise InvalidAuthorizationServer, "issuer mismatch: #{metadata_issuer} != #{request_issuer}"
        end
      end
    end
  end
end
