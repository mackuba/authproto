# frozen_string_literal: true

require 'json'
require 'minisky'
require 'net/http'
require 'uri'

require_relative 'client'
require_relative 'http_helpers'

#
# Experimental Minisky client backed by an AuthProto session.
# Requiring authproto alone does not load Minisky or this integration.
#

class Minisky::OAuthClient
  include AuthProto::HTTPHelpers
  include Minisky::Requests

  # Maximum authenticated XRPC retries after nonce challenges.
  # @return [Integer]
  MAX_NONCE_RETRIES = 2

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
  # @param client_id [String] OAuth client metadata URL or localhost client ID
  # @param redirect_uri [String, URI::Generic] registered callback URI
  # @param metadata [Hash{String => Object}, nil] preloaded metadata, or `nil` to fetch it
  # @param signing_key [Hash, JOSE::JWK, nil] private ES256 key for confidential-client authentication
  # @param session_id [String, nil] stored session ID to resume; `nil` starts without an attached session
  #
  # @raise [Minisky::AuthError] if a supplied session ID cannot be restored
  # @raise [AuthProto::InvalidClientMetadata] if metadata is invalid or unavailable
  # @raise [AuthProto::Error] if OAuth client or DPoP initialization fails
  # @raise [AuthProto::HTTPClient::HTTPError, AuthProto::HTTPClient::SSRFError] if fetching metadata fails
  # @see AuthProto::Client#initialize
  #
  def initialize(client_id:, redirect_uri:, metadata: nil, signing_key: nil, session_id: nil)
    @host = nil
    @session_id = session_id

    @send_auth_headers = true
    @auto_manage_tokens = false

    @oauth_client = AuthProto::Client.new(
      client_id: client_id,
      redirect_uri: redirect_uri,
      metadata: metadata,
      signing_key: signing_key
    )

    if session_id
      session = @oauth_client.session_manager.get_session(session_id)
      raise Minisky::AuthError, "OAuth session not found" unless session

      @host = session.pds
    end
  end

  # Returns the PDS URL of the authenticated user.
  #
  # @return [String] session's PDS URL
  # @raise [Minisky::AuthError] if the PDS is not known yet
  #
  def host
    if @host.nil?
      raise Minisky::AuthError, "Client has not completed authentication yet"
    end

    @host
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
  # @option options [String] :pds PDS URL, as an alternative to `handle`
  # @option options [String] :scope ('atproto') requested scopes
  #
  # @return [Hash{Symbol => String}] `:url` to open and pending `:session_id`
  # @raise [AuthProto::Error] if authorization, discovery, PAR or persistence fails
  # @see AuthProto::Client#authorize
  #
  def authorize(**options)
    result = oauth_client.authorize(**options)
    @session_id = result.fetch(:session_id)

    result
  end

  # Completes OAuth authorization and remembers the authenticated session ID.
  #
  # @param expected_session_id [String] pending session ID retained in the initiating browser session or native context
  # @param callback_params [Hash{String, Symbol => Object}] callback query parameters from the URL the user gets
  #    redirected to after authorization (should contain `code`, `state` and `iss`, or `error`)
  #
  # @return [Hash{Symbol => String, Integer, nil}] token and session details from the OAuth client
  # @raise [AuthProto::Client::CallbackError] if expected session, state or issuer validation fails
  # @raise [AuthProto::Client::TokenError] if token exchange or validation fails
  # @raise [AuthProto::Error] if proofs, storage or serialization fail
  # @see AuthProto::Client#handle_callback
  #
  def handle_callback(callback_params, expected_session_id:)
    result = oauth_client.handle_callback(callback_params, expected_session_id: expected_session_id)
    @session_id = result.fetch(:session_id)
    @host = result.fetch(:pds)

    result
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
  # @raise [AuthProto::DPoP::Client::Error] if proof handling fails or any DPoP response lacks a valid nonce
  # @raise [AuthProto::Error] if OAuth refresh or token persistence fails
  # @raise [JSON::ParserError] if a JSON response cannot be parsed
  # @raise [Net::OpenTimeout, Net::ReadTimeout, IOError, SystemCallError] if HTTP transport fails
  #
  def get_request(method, params = nil, auth: default_auth_mode, headers: nil)
    return super unless auth

    raise ArgumentError, "OAuth requests accept auth: true or false, not a bearer token" unless auth == true

    uri = build_request_uri(method).dup
    uri.query = URI.encode_www_form(params) if params && !params.empty?

    response = oauth_request(Net::HTTP::Get, uri, headers || {})
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
  # @raise [AuthProto::DPoP::Client::Error] if proof handling fails or any DPoP response lacks a valid nonce
  # @raise [AuthProto::Error] if OAuth refresh or token persistence fails
  # @raise [JSON::ParserError] if a JSON response cannot be parsed
  # @raise [Net::OpenTimeout, Net::ReadTimeout, IOError, SystemCallError] if HTTP transport fails
  #
  def post_request(method, data = nil, auth: default_auth_mode, headers: nil, params: nil)
    return super unless auth

    raise ArgumentError, "OAuth requests accept auth: true or false, not a bearer token" unless auth == true

    uri = build_request_uri(method).dup
    uri.query = URI.encode_www_form(params) if params && !params.empty?
    headers = (headers || {}).dup

    body = if data.is_a?(String) || data.nil?
             data.to_s
           else
             unless headers.keys.any? { |key| key.to_s.downcase == "content-type" }
               headers["Content-Type"] = "application/json"
             end
             data.to_json
           end

    response = oauth_request(Net::HTTP::Post, uri, headers, body: body)
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
  # @raise [AuthProto::DPoP::Client::Error] if a refresh response has a missing or invalid nonce
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

    if !session || session.pending?
      raise Minisky::AuthError, "Complete OAuth login before making authenticated requests"
    elsif session.tokens_valid?
      :ok
    elsif session.renewable?
      perform_token_refresh
      :refreshed
    else
      raise Minisky::AuthError, "OAuth session cannot be refreshed; log in again"
    end
  end


  private

  def oauth_request(request_class, uri, headers, body: nil)
    check_access

    nonce_retries = 0
    refreshed = false

    loop do
      # Fresh proof for every attempt; callers cannot override OAuth auth headers.
      request_headers = headers.reject { |k, v| %w[authorization dpop].include?(k.to_s.downcase) }
      request_headers.merge!(oauth_client.auth_headers(
                               session_id: session_id, method: request_class::METHOD, url: uri
                             ))

      request = request_class.new(uri, request_headers)
      request.body = body unless body.nil?

      response = make_request(request)
      response_hash = { status: response.code, headers: response.each_header.to_h, body: response.body }

      oauth_client.process_dpop(response_hash, url: uri, session_id: session_id)

      if oauth_client.has_nonce_error?(response_hash)
        return response if nonce_retries >= MAX_NONCE_RETRIES
        nonce_retries += 1
      else
        error = authentication_error(response)

        if response.code.to_i == 401 && error == "invalid_token" && !refreshed
          perform_token_refresh
          refreshed = true
        else
          return response
        end
      end
    end
  end

  def authentication_error(response)
    authentication_challenge(response['WWW-Authenticate'], scheme: 'DPoP')&.fetch('error', nil)
  end
end
