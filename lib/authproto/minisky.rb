# frozen_string_literal: true

require 'json'
require 'minisky'
require 'net/http'
require 'uri'

require_relative 'client'

#
# Experimental Minisky client backed by an AuthProto session.
# Requiring authproto alone does not load Minisky or this integration.
#

class Minisky::OAuthClient
  include Minisky::Requests

  # Maximum authenticated XRPC retries after nonce challenges.
  # @return [Integer]
  MAX_NONCE_RETRIES = 2

  # PDS host or base URL used by Minisky.
  # @return [String]
  attr_reader :host

  # OAuth client that owns the session, tokens and DPoP key.
  # @return [AuthProto::Client]
  attr_reader :oauth_client

  # Most recent authorization/callback session ID; `nil` before authorization.
  # @return [String, nil]
  attr_reader :session_id

  # Creates an experimental Minisky client backed by an OAuth session.
  #
  # Disables Minisky's app-password token management and enables authenticated
  # requests by default. Configure AuthProto's global storage/transport separately.
  #
  # @param host [String] PDS host or base URL used for XRPC requests
  # @param client_id [String] OAuth client metadata URL or localhost client ID
  # @param redirect_uri [String] registered callback URI
  # @param metadata [Hash{String => Object}, nil] preloaded metadata, or `nil` to fetch it
  # @param signing_key [Hash, JOSE::JWK, nil] private ES256 key for confidential-client authentication
  # @param dpop_key [Hash{String => Object}, nil] existing private DPoP JWK, or `nil` to generate one
  #
  # @raise [AuthProto::InvalidClientMetadata] if metadata is invalid or unavailable
  # @raise [AuthProto::Error] if OAuth client or DPoP initialization fails
  # @raise [AuthProto::HTTPClient::HTTPError, AuthProto::HTTPClient::SSRFError] if fetching metadata fails
  # @see AuthProto::Client#initialize
  #
  def initialize(host, client_id:, redirect_uri:, metadata: nil, dpop_key: nil, signing_key: nil, session_id: nil)
    @host = host
    @session_id = session_id

    @send_auth_headers = true
    @auto_manage_tokens = false

    @oauth_client = AuthProto::Client.new(
      client_id: client_id,
      redirect_uri: redirect_uri,
      metadata: metadata,
      dpop_key: dpop_key,
      signing_key: signing_key
    )
  end

  # Returns no app-password credential configuration; OAuth owns this client's tokens.
  # @return [nil]
  def config
    nil
  end

  # Starts OAuth authorization and remembers the pending session ID.
  #
  # @param options [Hash{Symbol => Object}] options forwarded to {AuthProto::Client#authorize}
  # @option options [String] :handle account handle, optionally prefixed with `@`
  # @option options [String] :pds_url PDS URL, as an alternative to `handle`
  # @option options [String] :scope ("atproto") requested scopes
  #
  # @return [Hash{Symbol => String}] `:url` to open and pending `:session_id`
  # @raise [AuthProto::Error] if authorization, discovery, PAR or persistence fails
  # @see AuthProto::Client#authorize
  #
  def authorize(**options)
    oauth_client.authorize(**options).tap { |result| @session_id = result.fetch(:session_id) }
  end

  # Completes OAuth authorization and remembers the authenticated session ID.
  #
  # @param options [Hash{Symbol => String}] callback parameters forwarded to {AuthProto::Client#handle_callback}
  # @option options [String] :code authorization code
  # @option options [String] :state callback state token
  # @option options [String] :iss authorization server issuer
  #
  # @return [Hash{Symbol => String, Integer, nil}] token and session details from the OAuth client
  # @raise [AuthProto::Client::CallbackError] if state or issuer validation fails
  # @raise [AuthProto::Client::TokenError] if token exchange or validation fails
  # @raise [AuthProto::Error] if proofs, storage or serialization fail
  # @see AuthProto::Client#handle_callback
  #
  def handle_callback(**options)
    oauth_client.handle_callback(**options).tap { |result| @session_id = result.fetch(:session_id) }
  end

  # Sends an XRPC GET through Minisky, adding OAuth handling when authenticated.
  #
  # Authenticated requests check token expiry, generate a fresh DPoP proof for each
  # attempt, retry at most {MAX_NONCE_RETRIES} nonce challenges, and refresh once on
  # an `invalid_token` response. `auth: false` delegates to Minisky without OAuth.
  #
  # @param method [String, URI::HTTP] XRPC NSID or URL accepted by Minisky
  # @param params [Hash, nil] query parameters encoded using `URI.encode_www_form`
  # @param auth [Boolean] whether to authenticate; defaults to Minisky's auth mode
  # @param headers [Hash{String => String}, nil] custom headers; OAuth authorization/proof headers are replaced
  #
  # @return [Hash, Array, String, Numeric, Boolean, nil] parsed JSON or raw response body returned by Minisky
  # @raise [ArgumentError] if the method is invalid or `auth` is a truthy non-Boolean value
  # @raise [Minisky::AuthError] if no completed OAuth login or refresh capability is available
  # @raise [Minisky::BadResponse] if the final response has an error or redirect status
  # @raise [AuthProto::DPoP::Client::Error] if proof handling fails or a nonce challenge lacks its nonce
  # @raise [AuthProto::Error] if OAuth refresh or token persistence fails
  # @raise [JSON::ParserError] if a JSON response cannot be parsed
  # @raise [Net::OpenTimeout, Net::ReadTimeout, IOError, SystemCallError] if HTTP transport fails
  #
  def get_request(method, params = nil, auth: default_auth_mode, headers: nil)
    return super unless auth

    raise ArgumentError, "OAuth requests accept auth: true or false, not a bearer token" unless auth == true

    url = build_request_uri(method).dup
    url.query = URI.encode_www_form(params) if params && !params.empty?

    response = oauth_request(Net::HTTP::Get, url, headers || {})
    handle_response(response)
  end

  # Sends an XRPC POST through Minisky, adding OAuth handling when authenticated.
  #
  # Authenticated requests check token expiry, generate a fresh DPoP proof for each
  # attempt, retry at most {MAX_NONCE_RETRIES} nonce challenges, and refresh once on
  # an `invalid_token` response. `auth: false` delegates to Minisky without OAuth.
  # Non-string data is JSON-encoded, adding `Content-Type: application/json` unless
  # a content type was supplied. Strings are transmitted unchanged.
  #
  # @param method [String, URI::HTTP] XRPC NSID or URL accepted by Minisky
  # @param data [String, #to_json, nil] raw body bytes, JSON-encodable data, or no body
  # @param params [Hash, nil] query parameters encoded using `URI.encode_www_form`
  # @param auth [Boolean] whether to authenticate; defaults to Minisky's auth mode
  # @param headers [Hash{String => String}, nil] custom headers; OAuth authorization/proof headers are replaced
  #
  # @return [Hash, Array, String, Numeric, Boolean, nil] parsed JSON or raw response body returned by Minisky
  # @raise [ArgumentError] if the method is invalid or `auth` is a truthy non-Boolean value
  # @raise [Minisky::AuthError] if no completed OAuth login or refresh capability is available
  # @raise [Minisky::BadResponse] if the final response has an error or redirect status
  # @raise [AuthProto::DPoP::Client::Error] if proof handling fails or a nonce challenge lacks its nonce
  # @raise [AuthProto::Error] if OAuth refresh or token persistence fails
  # @raise [JSON::ParserError] if a JSON response cannot be parsed
  # @raise [Net::OpenTimeout, Net::ReadTimeout, IOError, SystemCallError] if HTTP transport fails
  #
  def post_request(method, data = nil, auth: default_auth_mode, headers: nil, params: nil)
    return super unless auth

    raise ArgumentError, "OAuth requests accept auth: true or false, not a bearer token" unless auth == true

    url = build_request_uri(method).dup
    url.query = URI.encode_www_form(params) if params && !params.empty?
    headers = (headers || {}).dup

    body = if data.is_a?(String) || data.nil?
             data.to_s
           else
             unless headers.keys.any? { |key| key.to_s.downcase == "content-type" }
               headers["Content-Type"] = "application/json"
             end
             data.to_json
           end

    response = oauth_request(Net::HTTP::Post, url, headers, body: body)
    handle_response(response)
  end

  # Rejects Minisky's app-password login entry point.
  #
  # Accepts and ignores any arguments. Use {#authorize} and {#handle_callback} for OAuth login.
  #
  # @return [void]
  # @raise [NotImplementedError] always
  #
  def log_in(*)
    raise NotImplementedError, "Use authorize and handle_callback for OAuth login"
  end

  # Refreshes and persists tokens for the current session via the OAuth client.
  #
  # @return [Hash{Symbol => String, Integer, nil}] replacement tokens and session ID
  # @raise [AuthProto::Client::TokenError] if the session cannot be refreshed
  # @raise [AuthProto::Token::RefreshError] if refresh fails
  # @raise [AuthProto::Storage::StorageError] if token persistence fails
  #
  def perform_token_refresh
    oauth_client.refresh_token(session_id)
  end

  # Checks the OAuth login and refreshes an expired access token if possible.
  #
  # @return [Symbol] `:ok` for a usable token, or `:refreshed` after successful refresh
  # @raise [Minisky::AuthError] if login is incomplete or expired tokens cannot be refreshed
  # @raise [AuthProto::Error] if token refresh, serialization or persistence fails
  #
  def check_access
    session = oauth_client.session_manager.get_session(session_id) if session_id
    raise Minisky::AuthError, "Complete OAuth login before making authenticated requests" unless session&.tokens

    return :ok unless session.tokens.expired?

    raise Minisky::AuthError, "OAuth session cannot be refreshed; log in again" unless session.renewable?

    perform_token_refresh
    :refreshed
  end


  private

  def oauth_request(request_class, url, headers, body: nil)
    check_access

    nonce_retries = 0
    refreshed = false

    proof_url = url.dup
    proof_url.query = nil
    proof_url.fragment = nil

    loop do
      # Fresh proof for every attempt; callers cannot override OAuth auth headers.
      request_headers = headers.reject { |k, v| %w[authorization dpop].include?(k.to_s.downcase) }
      request_headers.merge!(oauth_client.auth_headers(
                               session_id: session_id, method: request_class::METHOD, url: proof_url.to_s
                             ))

      request = request_class.new(url, request_headers)
      request.body = body unless body.nil?
      response = make_request(request)

      nonce = response["DPoP-Nonce"]
      oauth_client.dpop_client.process_response(response.each_header.to_h, url.to_s) if nonce && !nonce.empty?
      error = authentication_error(response)

      if response.code.to_i == 401 && error == "use_dpop_nonce"
        unless nonce && !nonce.empty?
          raise AuthProto::DPoP::Client::Error, "DPoP nonce challenge (HTTP 401) is missing DPoP-Nonce"
        end
        return response if nonce_retries >= MAX_NONCE_RETRIES

        nonce_retries += 1
      elsif response.code.to_i == 401 && error == "invalid_token" && !refreshed
        perform_token_refresh
        refreshed = true
      else
        return response
      end
    end
  end

  def authentication_error(response)
    # Only interpret a single DPoP challenge. Leave other auth schemes and
    # ambiguous multi-challenge headers to Minisky's normal error handling.
    challenge = response["WWW-Authenticate"].to_s
    return unless challenge.match?(/\ADPoP\s/i)
    return if challenge.match?(/,\s*(?:Bearer|Basic|DPoP)\b/i)

    challenge[/\berror\s*=\s*"(use_dpop_nonce|invalid_token)"/i, 1]
  end
end
