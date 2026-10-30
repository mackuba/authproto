# frozen_string_literal: true

require 'json'
require 'jose'
require 'uri'

require_relative '../configuration'
require_relative '../errors'
require_relative '../metadata'
require_relative '../validated_uri'

module AuthProto

  #
  # Supported OAuth application types used by {Metadata::ClientMetadata}.
  #

  module ApplicationType

    # Application type for browser-based OAuth client applications
    WEB = "web"

    # Application type for native desktop or mobile OAuth client applications
    NATIVE = "native"

    # Supported application type values.
    # @return [Array<String>]
    ALL = [WEB, NATIVE].freeze
  end

  module Metadata

    #
    # Handles validation and management of AT Protocol OAuth client metadata according to
    # the specification. This includes required fields like client_id and redirect URIs,
    # optional metadata like client name and logo, and authentication configuration for
    # confidential clients. Validates that all fields conform to the protocol's requirements,
    # including:
    #
    # - Application type (web/native) validation and redirect URI rules
    # - Required scopes and grant types
    # - JWKS configuration for confidential clients
    # - DPoP binding requirements
    # - URI scheme and format validation
    #

    class ClientMetadata

      # Client authentication method for confidential clients
      AUTH_METHOD_PRIVATE_KEY_JWT = "private_key_jwt"

      # Client authentication method value for public clients
      AUTH_METHOD_NONE = "none"

      # RFC 6749 scope-token characters, separated by single ASCII spaces.
      SCOPE_PATTERN = /\A[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*\z/


      # -- required fields --

      # Client metadata URL or localhost client identifier. **Required**.
      # @return [String]
      attr_reader :client_id

      # List of allowed grant types. ATProto requires `authorization_code` and supports `refresh_token`. **Required**.
      # @return [Array<String>]
      attr_reader :grant_types

      # List of supported response types. In ATProto, it must include `code`. **Required**.
      # @return [Array<String>]
      attr_reader :response_types

      # List of registered OAuth callback URIs. **Required**.
      # @return [Array<String>]
      attr_reader :redirect_uris

      # Space-separated list of supported OAuth scopes. Must include at least `atproto`. **Required**.
      # @return [String]
      attr_reader :scope

      # Client authentication method: `none` for public clients, or `private_key_jwt` for confidential ones.
      # Not technically required, but the reference PDS sets it to `client_secret_basic` if not set,
      # which we don't support.
      # @return [String]
      attr_reader :token_endpoint_auth_method


      # -- optional fields --

      # Application type: `web` (default) or `native`.
      # @return [String]
      attr_reader :application_type

      # Public name of the client application that is presented to the user, if supplied.
      # @return [String, nil]
      attr_reader :client_name

      # URL of the client application's home page, if supplied.
      # @return [String, nil]
      attr_reader :client_uri

      # URL to the client application's logo image, if supplied.
      # @return [String, nil]
      attr_reader :logo_uri

      # URL to human-readable terms of service of the client, if supplied.
      # @return [String, nil]
      attr_reader :tos_uri

      # URL to human-readable privacy policy of the client, if supplied.
      # @return [String, nil]
      attr_reader :policy_uri

      # Inline set of JWK keys for confidential clients, if supplied.
      # @return [Hash{String => Object}, nil]
      attr_reader :jwks

      # HTTPS URL to a set of JWK keys for confidential clients, if supplied.
      # @return [String, nil]
      attr_reader :jwks_uri


      # Validates string-keyed client metadata and exposes its fields.
      #
      # Requires `client_id`, `grant_types`, `response_types`, `redirect_uris`, `scope`,
      # `token_endpoint_auth_method`, and `dpop_bound_access_tokens: true`.
      # `application_type` defaults to `web`.
      # Confidential clients using `private_key_jwt` require `ES256` and a JWK set or URI.
      #
      # @param metadata [Hash{String => Object}] parsed OAuth client metadata
      # @raise [InvalidClientMetadata] if a required field or supported value is invalid
      # @raise [URI::InvalidURIError] if a metadata URI cannot be parsed
      #
      def initialize(metadata)
        validate_and_set_metadata(metadata)
      end

      # Fetches and validates a client metadata document using the configured transport.
      #
      # Requires HTTP 200 and application/json, without following redirects.
      # The document's `client_id` must equal the requested URL.
      # Localhost HTTP client IDs generate virtual metadata without a network request.
      #
      # @param url [String] HTTPS metadata URL, or localhost URL for development
      # @return [ClientMetadata] validated metadata
      # @raise [InvalidClientMetadata] if metadata is missing, invalid/mismatched, not JSON,
      #   or transport isn't configured
      # @raise [HTTPClient::HTTPError, HTTPClient::SSRFError] if the transport rejects/fails the request
      # @raise [URI::InvalidURIError] if a URL cannot be parsed
      #
      def self.from_url(url)
        uri = ValidatedURI.new(url)

        unless uri.scheme == 'https' || (uri.scheme == 'http' && uri.host == 'localhost')
          raise InvalidClientMetadata, "client_id must use HTTPS except for localhost"
        end

        return from_localhost_url(url) if uri.scheme == 'http'

        raise InvalidClientMetadata, "HTTP client not configured" unless AuthProto.configuration.http_client

        response = AuthProto.configuration.http_client.get(url, follow_redirects: false)

        unless response[:status] == 200
          raise InvalidClientMetadata,
            "expected HTTP 200 response for client metadata request, got #{response[:status]}"
        end

        content_type = (response[:headers] || {}).find { |name, _| name.downcase == 'content-type' }&.last

        unless content_type.to_s.split(';', 2).first.to_s.strip.downcase == 'application/json'
          raise InvalidClientMetadata, "client metadata Content-Type must be application/json"
        end

        raise InvalidClientMetadata, "client metadata request returned response with no body" if response[:body].nil?

        metadata = JSON.parse(response[:body])
        raise InvalidClientMetadata, "metadata must be a hash" unless metadata.is_a?(Hash)

        if metadata['client_id'] != url
          raise InvalidClientMetadata, "client_id mismatch: #{metadata['client_id']} != #{url}"
        end

        self.new(metadata)
      rescue JSON::ParserError => e
        raise InvalidClientMetadata, "Invalid JSON in client metadata: #{e.message}"
      end

      def self.from_localhost_url(url)
        uri = ValidatedURI.new(url)
        params = URI.decode_www_form(uri.query.to_s)

        scopes = params.select { |k, v| k == 'scope' }.map(&:last)

        if scopes.length > 1
          raise InvalidClientMetadata, "localhost client_id must not contain multiple scope parameters"
        end

        redirects = params.select { |k, v| k == 'redirect_uri' }.map(&:last)
        redirects = ['http://127.0.0.1/', 'http://[::1]/'] if redirects.empty?

        self.new(
          'client_id' => url,
          'client_name' => 'Development client',
          'application_type' => ApplicationType::NATIVE,
          'token_endpoint_auth_method' => AUTH_METHOD_NONE,
          'dpop_bound_access_tokens' => true,
          'grant_types' => ['authorization_code', 'refresh_token'],
          'response_types' => ['code'],
          'scope' => scopes.first || 'atproto',
          'redirect_uris' => redirects
        )
      rescue ArgumentError => e
        raise InvalidClientMetadata, "Invalid localhost client_id query: #{e.message}"
      end

      private_class_method :from_localhost_url

      # Determines if the client is confidential (has authentication keys).
      # @return [Boolean] true if client is confidential.
      #
      def confidential?
        token_endpoint_auth_method == AUTH_METHOD_PRIVATE_KEY_JWT
      end


      private

      def validate_and_set_metadata(metadata)
        raise InvalidClientMetadata, "metadata must be a hash" unless metadata.is_a?(Hash)

        # Optional (defaults to "web"), but must be set before validating redirect URIs
        @application_type = validate_application_type(metadata['application_type'])

        # Required fields
        @client_id = validate_client_id(metadata['client_id'])
        @grant_types = validate_grant_types(metadata['grant_types'])
        @response_types = validate_response_types(metadata['response_types'])
        @redirect_uris = validate_redirect_uris(metadata['redirect_uris'])
        @scope = validate_scope(metadata['scope'])

        # Check dpop_bound_access_tokens
        validate_dpop(metadata)

        # Optional fields
        @client_name = validate_client_name(metadata['client_name'])
        @client_uri = validate_client_uri(metadata['client_uri'])
        @logo_uri = validate_https_uri(metadata['logo_uri'])
        @tos_uri = validate_https_uri(metadata['tos_uri'])
        @policy_uri = validate_https_uri(metadata['policy_uri'])

        # Check token_endpoint_auth_method and jwks
        validate_auth_methods(metadata)
      end


      # -- Required field validations --

      def validate_client_id(client_id)
        raise InvalidClientMetadata, "client_id is required" unless client_id
        raise InvalidClientMetadata, "client_id must be a string" unless client_id.is_a?(String)

        unless valid_https_client_id?(client_id) || valid_localhost_client_id?(client_id)
          raise InvalidClientMetadata, "client_id must be HTTPS or localhost HTTP URL"
        end

        client_id
      end

      def valid_https_client_id?(client_id)
        uri = ValidatedURI.new(client_id)
        uri.scheme == 'https' && !uri.port && !uri.userinfo && !uri.fragment
      rescue URI::InvalidURIError
        false
      end

      def valid_localhost_client_id?(client_id)
        uri = ValidatedURI.new(client_id)
        uri.scheme == 'http' && uri.host == 'localhost' && !uri.port && !uri.userinfo &&
          !uri.fragment && uri.path.empty?
      rescue URI::InvalidURIError
        false
      end

      def validate_grant_types(grant_types)
        raise InvalidClientMetadata, "grant_types is required" unless grant_types
        raise InvalidClientMetadata, "grant_types must be an array" unless grant_types.is_a?(Array)

        unless grant_types.include?('authorization_code')
          raise InvalidClientMetadata, "grant_types must include authorization_code"
        end

        valid_types = %w[authorization_code refresh_token]

        grant_types.each do |grant|
          raise InvalidClientMetadata, "unsupported grant type" unless valid_types.include?(grant)
        end

        grant_types
      end

      def validate_response_types(response_types)
        raise InvalidClientMetadata, "response_types is required" unless response_types
        raise InvalidClientMetadata, "response_types must be an array" unless response_types.is_a?(Array)
        raise InvalidClientMetadata, "response_types must include 'code'" unless response_types.include?('code')

        unless response_types.all? { |type| type.is_a?(String) }
          raise InvalidClientMetadata, "response_types must contain only strings"
        end

        response_types
      end

      def validate_redirect_uris(uris)
        raise InvalidClientMetadata, "redirect_uris is required" unless uris
        raise InvalidClientMetadata, "redirect_uris must be an array" unless uris.is_a?(Array)
        raise InvalidClientMetadata, "redirect_uris must not be empty" if uris.empty?

        uris.each { |uri| validate_redirect_uri(uri) }
        uris
      end

      def validate_redirect_uri(url)
        raise InvalidClientMetadata, "redirect_uris entries must be strings" unless url.is_a?(String)

        case application_type
        when ApplicationType::WEB
          validate_https_redirect_uri(url)
        when ApplicationType::NATIVE
          validate_native_redirect_uri(url)
        end
      rescue URI::InvalidURIError => e
        raise InvalidClientMetadata, "Invalid redirect URI: #{e.message}"
      end

      def validate_https_redirect_uri(url)
        uri = ValidatedURI.new(url)

        unless uri.scheme == 'https'
          raise InvalidClientMetadata, "redirect URI must use HTTPS with a hostname"
        end

        raise InvalidClientMetadata, "redirect URI must not contain credentials" if uri.userinfo
        raise InvalidClientMetadata, "redirect URI must not contain a fragment" if uri.fragment

        if uri.specified_port && uri.effective_port == 443
          raise InvalidClientMetadata, "HTTPS redirect URI must not specify the default port"
        end
      end

      def validate_redirect_uri_origin(url)
        client_uri = ValidatedURI.new(@client_id)
        uri = ValidatedURI.new(url)

        unless uri.origin.downcase == client_uri.origin.downcase
          raise InvalidClientMetadata, "redirect URI must match client_id origin"
        end
      end

      def validate_native_redirect_uri(url)
        uri = URI(url)

        case uri.scheme
        when 'https'
          validate_https_redirect_uri(url)
          validate_redirect_uri_origin(url)
        when 'http'
          uri = ValidatedURI.new(url)
          raise InvalidClientMetadata, "redirect URI must not contain credentials" if uri.userinfo
          raise InvalidClientMetadata, "redirect URI must not contain a fragment" if uri.fragment

          unless ["127.0.0.1", "[::1]"].include?(uri.host)
            raise InvalidClientMetadata, "HTTP redirect URIs for native clients must use loopback IP"
          end

          unless uri.effective_port.between?(1, 65_535)
            raise InvalidClientMetadata, "HTTP redirect URI must have a valid port"
          end
        else
          validate_custom_scheme(uri)
        end
      end

      def validate_custom_scheme(uri)
        reversed_host = URI(@client_id).host.downcase.split('.').reverse.join('.')

        unless uri.scheme == reversed_host
          raise InvalidClientMetadata, "custom scheme must match reversed client_id domain"
        end

        unless uri.scheme.include?('.')
          raise InvalidClientMetadata, "custom scheme must include a '.'"
        end

        unless !uri.host && uri.path && uri.path.start_with?('/')
          raise InvalidClientMetadata, "custom scheme redirect URI must use a single slash after the scheme"
        end

        raise InvalidClientMetadata, "redirect URI must not contain a fragment" if uri.fragment
      end

      def validate_scope(scope)
        raise InvalidClientMetadata, "scope is required" unless scope
        raise InvalidClientMetadata, "scope must be a string" unless scope.is_a?(String)

        unless SCOPE_PATTERN.match?(scope)
          raise InvalidClientMetadata, "scope must contain valid tokens separated by single spaces"
        end

        scope_values = scope.split(' ')
        raise InvalidClientMetadata, "atproto scope is required" unless scope_values.include?('atproto')

        scope
      end

      def validate_dpop(metadata)
        unless metadata["dpop_bound_access_tokens"] == true
          raise InvalidClientMetadata, "dpop_bound_access_tokens must be true"
        end
      end


      # -- Optional field validations --

      def validate_application_type(type)
        if ApplicationType::ALL.include?(type)
          type
        elsif type.nil?
          ApplicationType::WEB
        else
          raise InvalidClientMetadata, "application_type must be 'web' or 'native'"
        end
      end

      def validate_client_name(name)
        return if name.nil?
        raise InvalidClientMetadata, "client_name must be a string, if provided" unless name.is_a?(String)

        name
      end

      def validate_client_uri(uri)
        return if uri.nil?
        raise InvalidClientMetadata, "client_uri must be a string" unless uri.is_a?(String)

        parsed = ValidatedURI.new(uri)

        unless parsed.origin == URI(@client_id).origin
          raise InvalidClientMetadata, "client_uri must have the same hostname as client_id"
        end

        uri
      rescue URI::InvalidURIError
        raise InvalidClientMetadata, "client_uri must use HTTP or HTTPS and must have the same hostname as client_id"
      end

      def validate_https_uri(uri)
        return if uri.nil?

        raise InvalidClientMetadata, "URI must be a string" unless uri.is_a?(String)

        parsed = ValidatedURI.new(uri)
        raise InvalidClientMetadata, "URI must use HTTPS" unless parsed.scheme == 'https'

        uri
      rescue URI::InvalidURIError
        raise InvalidClientMetadata, "URI must use HTTPS with a hostname"
      end

      def validate_jwks(jwks)
        raise InvalidClientMetadata, "jwks must be a hash" unless jwks.is_a?(Hash)
        raise InvalidClientMetadata, "jwks must have a 'keys' array" unless jwks['keys'].is_a?(Array)
        raise InvalidClientMetadata, "jwks must contain at least one public key" if jwks['keys'].empty?

        jwks['keys'].each_with_index do |key, index|
          path = "jwks.keys.#{index}"

          raise InvalidClientMetadata, "#{path} must be a hash" unless key.is_a?(Hash)

          unless key['kid'].is_a?(String) && !key['kid'].empty?
            raise InvalidClientMetadata, "#{path} must have a nonempty string kid"
          end

          if %w[d p q dp dq qi oth k].any? { |field| key.key?(field) }
            raise InvalidClientMetadata, "#{path} must contain only public key material"
          end

          if key.key?('use') && !%w[sig enc].include?(key['use'])
            raise InvalidClientMetadata, "#{path}.use must be sig or enc"
          end

          if key.key?('key_ops')
            raise InvalidClientMetadata, "#{path}.key_ops must be an array" unless key['key_ops'].is_a?(Array)

            operations = key['key_ops']
            unless !operations.empty? && operations.uniq == operations &&
                   operations.all? { |operation| %w[verify encrypt wrapKey].include?(operation) }
              raise InvalidClientMetadata,
                "#{path}.key_ops must contain distinct public operations: verify, encrypt or wrapKey"
            end

            if (key['use'] == 'sig' && operations.any? { |operation| operation != 'verify' }) ||
               (key['use'] == 'enc' && operations.include?('verify'))
              raise InvalidClientMetadata, "#{path}.key_ops must be consistent with use"
            end
          end

          fields = case key['kty']
                   when 'EC' then %w[crv x y]
                   when 'RSA' then %w[n e]
                   when 'OKP' then %w[crv x]
                   else
                     raise InvalidClientMetadata, "#{path} must be an asymmetric public JWK"
                   end

          unless fields.all? { |field| key[field].is_a?(String) && !key[field].empty? }
            raise InvalidClientMetadata, "#{path} is missing public key material"
          end

          begin
            JOSE::JWK.from_map(key).to_public
          rescue StandardError
            raise InvalidClientMetadata, "#{path} contains invalid public key material"
          end
        end
      end


      # -- Auth fields validations --

      def validate_auth_methods(metadata)
        @token_endpoint_auth_method = metadata['token_endpoint_auth_method']
        @token_endpoint_auth_signing_alg = metadata['token_endpoint_auth_signing_alg']

        raise InvalidClientMetadata, "token_endpoint_auth_method is required" if @token_endpoint_auth_method.nil?

        @jwks = metadata['jwks']
        @jwks_uri = metadata['jwks_uri']

        if !@jwks.nil? && !@jwks_uri.nil?
          raise InvalidClientMetadata, "cannot use both jwks and jwks_uri"
        end

        validate_jwks(@jwks) unless @jwks.nil?
        validate_https_uri(@jwks_uri) unless @jwks_uri.nil?

        case @token_endpoint_auth_method
        when AUTH_METHOD_NONE
          validate_auth_public(metadata)
        when AUTH_METHOD_PRIVATE_KEY_JWT
          validate_auth_confidential(metadata)
        else
          raise InvalidClientMetadata, "unsupported token_endpoint_auth_method"
        end
      end

      def validate_auth_public(metadata)
        unless @token_endpoint_auth_signing_alg.nil?
          raise InvalidClientMetadata, "token_endpoint_auth_signing_alg must be unset for public clients"
        end
      end

      def validate_auth_confidential(metadata)
        unless @token_endpoint_auth_signing_alg == 'ES256'
          raise InvalidClientMetadata, "token_endpoint_auth_signing_alg must be ES256"
        end

        if @jwks.nil? && @jwks_uri.nil?
          raise InvalidClientMetadata, "confidential clients must provide jwks or jwks_uri"
        end
      end
    end
  end
end
