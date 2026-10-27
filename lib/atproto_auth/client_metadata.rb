# frozen_string_literal: true

require 'json'
require 'uri'

module AuthProto

  #
  # Supported OAuth application types used by {ClientMetadata}.
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
    AUTH_PRIVATE_KEY_JWT = "private_key_jwt"

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

    # Client authentication method; needs to be set to `private_key_jwt` for confidential clients.
    # @return [String, nil]
    attr_reader :token_endpoint_auth_method

    # Inline set of JWK keys for confidential clients, if supplied.
    # @return [Hash{String => Object}, nil]
    attr_reader :jwks

    # HTTPS URL to a set of JWK keys for confidential clients, if supplied.
    # @return [String, nil]
    attr_reader :jwks_uri


    # Validates string-keyed client metadata and exposes its fields.
    #
    # Requires `client_id`, `grant_types`, `response_types`, `redirect_uris`, `scope`,
    # and `dpop_bound_access_tokens: true`. `application_type` defaults to `web`.
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
    #
    # @param url [String] HTTPS metadata URL, or localhost URL for development
    # @return [ClientMetadata] validated metadata
    # @raise [InvalidClientMetadata] if metadata is missing, invalid/mismatched, not JSON, or transport isn't configured
    # @raise [HTTPClient::HTTPError, HTTPClient::SSRFError] if the transport rejects/fails the request
    # @raise [URI::InvalidURIError] if a URL cannot be parsed
    #
    def self.from_url(url)
      uri = URI(url)

      unless uri.scheme == 'https' || (uri.scheme == 'http' && uri.host == 'localhost')
        raise InvalidClientMetadata, "client_id must use HTTPS except for localhost"
      end

      raise InvalidClientMetadata, "HTTP client not configured" unless AuthProto.configuration.http_client

      response = AuthProto.configuration.http_client.get(url, follow_redirects: false)

      unless response[:status] == 200
        raise InvalidClientMetadata, "expected HTTP 200 response for client metadata request, got #{response[:status]}"
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

    # Determines if the client is confidential (has authentication keys).
    # @return [Boolean] true if client is confidential.
    #
    def confidential?
      token_endpoint_auth_method == AUTH_PRIVATE_KEY_JWT
    end


    private

    def validate_and_set_metadata(metadata)
      raise InvalidClientMetadata, "metadata must be a hash" unless metadata.is_a?(Hash)

      # Optional (defaults to "web"), but must be set before validating redirect URIs
      @application_type = validate_application_type(metadata["application_type"])

      # Required fields
      @client_id = validate_client_id(metadata["client_id"])
      @grant_types = validate_grant_types(metadata["grant_types"])
      @response_types = validate_response_types(metadata["response_types"])
      @redirect_uris = validate_redirect_uris(metadata["redirect_uris"])
      @scope = validate_scope(metadata["scope"])

      # Check dpop_bound_access_tokens
      validate_dpop(metadata)

      # Optional fields
      @client_name = validate_client_name(metadata["client_name"])
      @client_uri = validate_client_uri(metadata["client_uri"])
      @logo_uri = validate_https_uri(metadata["logo_uri"])
      @tos_uri = validate_https_uri(metadata["tos_uri"])
      @policy_uri = validate_https_uri(metadata["policy_uri"])

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
      uri = URI(client_id)
      userinfo, port = URI.split(client_id).values_at(1, 3)

      uri.scheme == 'https' && uri.host.to_s != '' && port.nil? && userinfo.nil? && !uri.fragment
    rescue URI::InvalidURIError
      false
    end

    def valid_localhost_client_id?(client_id)
      uri = URI(client_id)
      userinfo, port = URI.split(client_id).values_at(1, 3)

      uri.scheme == 'http' && uri.host == 'localhost' && port.nil? && userinfo.nil? && !uri.fragment &&
        uri.path.to_s.chomp('/').empty?
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
      raise InvalidClientMetadata, "response_types must include 'code'" unless response_types.include?("code")

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

    def validate_redirect_uri(value)
      raise InvalidClientMetadata, "redirect_uris entries must be strings" unless value.is_a?(String)

      uri = URI(value)
      userinfo, port = URI.split(value).values_at(1, 3)

      raise InvalidClientMetadata, "redirect URI must be absolute" unless uri.absolute?
      raise InvalidClientMetadata, "redirect URI must not contain credentials" unless userinfo.nil?
      raise InvalidClientMetadata, "redirect URI must not contain a fragment" unless uri.fragment.nil?

      case application_type
      when ApplicationType::WEB
        validate_https_redirect_uri(uri, port)
      when ApplicationType::NATIVE
        validate_native_redirect_uri(uri, port)
      end
    rescue URI::InvalidURIError => e
      raise InvalidClientMetadata, "Invalid redirect URI: #{e.message}"
    end

    def validate_https_redirect_uri(uri, port)
      unless uri.scheme == 'https' && !uri.host.to_s.empty?
        raise InvalidClientMetadata, "redirect URI must use HTTPS with a hostname"
      end

      if port && uri.port == 443
        raise InvalidClientMetadata, "HTTPS redirect URI must not specify the default port"
      end
    end

    def validate_redirect_uri_origin(uri)
      client_uri = URI(@client_id)

      unless uri.origin.downcase == client_uri.origin.downcase
        raise InvalidClientMetadata, "redirect URI must match client_id origin"
      end
    end

    def validate_native_redirect_uri(uri, port)
      case uri.scheme
      when 'https'
        validate_https_redirect_uri(uri, port)
        validate_redirect_uri_origin(uri)
      when 'http'
        unless ["127.0.0.1", "[::1]"].include?(uri.host)
          raise InvalidClientMetadata, "HTTP redirect URIs for native clients must use loopback IP"
        end
      else
        validate_custom_scheme(uri)
      end
    end

    def validate_custom_scheme(uri)
      reversed_host = URI(@client_id).host.downcase.split('.').reverse.join('.')

      unless uri.scheme.include?('.') && uri.scheme == reversed_host
        raise InvalidClientMetadata, "custom scheme must match reversed client_id domain"
      end

      unless uri.host.nil? && uri.path && uri.path.start_with?('/')
        raise InvalidClientMetadata, "custom scheme redirect URI must use a single slash after the scheme"
      end
    end

    def validate_scope(scope)
      raise InvalidClientMetadata, "scope is required" unless scope
      raise InvalidClientMetadata, "scope must be a string" unless scope.is_a?(String)
      raise InvalidClientMetadata, "scope must contain valid tokens separated by single spaces" unless SCOPE_PATTERN.match?(scope)

      scope_values = scope.split(' ')
      raise InvalidClientMetadata, "atproto scope is required" unless scope_values.include?("atproto")

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

      parsed = URI(uri)

      unless %w[http https].include?(parsed.scheme)
        raise InvalidClientMetadata, "client_uri must use HTTP or HTTPS"
      end

      unless URI(uri).origin == URI(@client_id).origin
        raise InvalidClientMetadata, "client_uri must have the same hostname as client_id"
      end

      uri
    end

    def validate_https_uri(uri)
      return if uri.nil?

      raise InvalidClientMetadata, "URI must be a string" unless uri.is_a?(String)

      parsed = URI(uri)
      raise InvalidClientMetadata, "URI must use HTTPS" unless parsed.scheme == "https" && !parsed.host.to_s.empty?

      uri
    end

    def validate_jwks(jwks)
      raise InvalidClientMetadata, "jwks must be a hash" unless jwks.is_a?(Hash)
      raise InvalidClientMetadata, "jwks must have a 'keys' array" unless jwks['keys'].is_a?(Array)

      jwks['keys'].each_with_index do |key, index|
        raise InvalidClientMetadata, "jwks.keys.#{index} must be a hash" unless key.is_a?(Hash)

        if key.key?('key_ops') && !key['key_ops'].is_a?(Array)
          raise InvalidClientMetadata, "jwks.keys.#{index}.key_ops must be an array"
        end

        has_key_use_sig = (key['use'] == 'sig')
        has_key_ops_sign = (key['key_ops']&.include?('sign'))

        if !has_key_use_sig && !has_key_ops_sign
          raise InvalidClientMetadata, "jwks.keys.#{index} must have use='sig' or key_ops including 'sign'"
        end

        raise InvalidClientMetadata, "jwks.keys.#{index} must have a 'kid' field" unless key['kid']
      end
    end

    def validate_auth_methods(metadata)
      @token_endpoint_auth_method = metadata["token_endpoint_auth_method"]
      @token_endpoint_auth_signing_alg = metadata["token_endpoint_auth_signing_alg"]

      case @token_endpoint_auth_method
      when nil, 'none'
        validate_auth_public(metadata)
      when AUTH_PRIVATE_KEY_JWT
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
      unless @token_endpoint_auth_signing_alg == "ES256"
        raise InvalidClientMetadata, "token_endpoint_auth_signing_alg must be ES256"
      end

      @jwks = metadata["jwks"]
      @jwks_uri = metadata["jwks_uri"]

      raise InvalidClientMetadata, "cannot use both jwks and jwks_uri" if @jwks && @jwks_uri
      raise InvalidClientMetadata, "confidential clients must provide jwks or jwks_uri" unless @jwks || @jwks_uri

      validate_jwks(@jwks) if @jwks
      validate_https_uri(@jwks_uri) if @jwks_uri
    end
  end
end
