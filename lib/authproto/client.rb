# frozen_string_literal: true

require 'didkit/did'
require 'jose'
require 'json'
require 'uri'

require_relative 'configuration'
require_relative 'dpop/client'
require_relative 'errors'
require_relative 'metadata/authorization_server'
require_relative 'metadata/client_metadata'
require_relative 'metadata/resource_server'
require_relative 'par'
require_relative 'par/client'
require_relative 'par/client_assertion'
require_relative 'par/request'
require_relative 'state/session_manager'
require_relative 'state/token_set'
require_relative 'storage/key_builder'
require_relative 'token/refresh'

module AuthProto

  #
  # Main client class for AT Protocol OAuth implementation. Handles the complete
  # OAuth flow including authorization, token management, and identity verification.
  #

  class Client

    # Error raised when authorization callback fails
    class CallbackError < Error; end

    # Error raised when token operations fail
    class TokenError < Error; end

    #
    # Error raised when session operations fail
    #

    class SessionError < Error

      # Identifier of the session associated with the failure, if known.
      # @return [String, nil]
      attr_reader :session_id

      # Creates a session error with an optional session identifier.
      #
      # @param message [String] explanation of the failure
      # @param session_id [String, nil] associated session ID
      #
      def initialize(message, session_id: nil)
        @session_id = session_id
        super(message)
      end
    end

    # OAuth client ID URL.
    # @return [String]
    attr_reader :client_id

    # Callback URI registered in the client metadata.
    # @return [String]
    attr_reader :redirect_uri

    # Validated client metadata.
    # @return [Metadata::ClientMetadata]
    attr_reader :client_metadata

    # Manager for stored OAuth sessions.
    # @return [State::SessionManager]
    attr_reader :session_manager

    # Shared DPoP proof generator and per-server nonce manager.
    # @return [DPoP::Client]
    attr_reader :dpop_client

    # Creates an OAuth client with shared DPoP helpers and a session manager.
    #
    # Configure {AuthProto.configure} with an HTTP transport before fetching metadata
    # or starting authorization. Session storage restores the DPoP key bound to each session.
    #
    # @param client_id [String] OAuth client ID URL
    # @param redirect_uri [String] callback URI listed in `redirect_uris`
    # @param metadata [Hash{String => Object}, nil] preloaded metadata, or `nil` to fetch `client_id`
    # @param signing_key [Hash, JOSE::JWK, nil] private ES256 client-authentication key, separate from public metadata
    #
    # @raise [InvalidClientMetadata] if client metadata is invalid or unavailable
    # @raise [Error] if the redirect URI is not registered
    # @raise [HTTPClient::HTTPError, HTTPClient::SSRFError] if fetching client metadata fails
    #
    def initialize(client_id:, redirect_uri:, metadata: nil, signing_key: nil)
      @client_id = client_id
      @redirect_uri = redirect_uri

      # Client metadata is fetched from .well-known if not provided directly
      @client_metadata = load_client_metadata(metadata)

      validate_redirect_uri
      initialize_signing_key(signing_key)

      @session_manager = State::SessionManager.new(supported_signing_key_ids: [@signing_key_kid].compact)
      @dpop_client = DPoP::Client.new
    end

    # Starts authorization, stores a pending session, and submits a PAR request.
    #
    # Supply exactly one of `handle` or `pds`. Open the returned `:url` in a browser
    # and pass the eventual callback parameters to {#handle_callback}. Retain `:session_id`
    # in the initiating browser session or native login context for callback verification.
    #
    # @param handle [String, nil] account handle (optionally prefixed with `@`) or DID
    # @param pds [String, nil] PDS URL when no handle is supplied
    # @param scope [String] space-separated scopes, which must all be declared in client metadata, including `atproto`
    #
    # @return [Hash{Symbol => String}] `:url` is the browser URL; `:session_id` identifies the pending session
    # @raise [Error] if identity arguments or scope are invalid, the handle cannot be verified, or no HTTPS PDS is found
    # @raise [DIDKit::DIDError, DIDKit::FormatError, DIDKit::APIError] if DID validation or document fetching fails
    # @raise [InvalidAuthorizationServer] if server discovery or metadata validation fails
    # @raise [PAR::Error] if the pushed authorization request fails
    # @raise [PAR::ClientAssertion::Error] if confidential-client signing fails
    # @raise [DPoP::Client::Error] if generating the PAR proof fails
    # @raise [HTTPClient::SSRFError] if server discovery rejects a destination
    # @raise [DPoP::KeySet::KeyError] if generating the session key fails
    # @raise [Storage::StorageError] if session storage or locking fails
    # @raise [Encryption::EncryptionError] if session serialization cannot encrypt secrets
    #
    def authorize(handle: nil, pds: nil, scope: 'atproto')
      validate_auth_params(handle, pds, scope)

      if !pds
        did = DIDKit::DID.resolve_handle(handle)
        raise Error, "Could not resolve or verify identity #{handle}" unless did

        pds = did.document.pds_endpoint
        raise Error, "No HTTPS PDS location found for #{did}" unless pds && URI(pds).is_a?(URI::HTTPS)
      end

      authorization_server = resolve_auth_server_info(pds)

      session = session_manager.create_session(
        client_id: @client_id,
        scope: scope,
        auth_server: authorization_server,
        did: did&.to_s,
        signing_key_id: @signing_key_kid
      )

      auth_url = submit_authorization_par(authorization_server, session, login_hint: handle)

      {
        url: auth_url,
        session_id: session.session_id
      }
    end

    # Validates a callback, exchanges its code, and stores the authenticated session.
    #
    # The result contains `:access_token` (String), `:token_type` (String, `DPoP`),
    # `:expires_in` (Integer seconds remaining), `:refresh_token` (String or nil),
    # and `:scope` (String).
    # It also contains `:session_id` (String) and `:did` (String).
    #
    # Supply the session ID retained when starting authorization as `expected_session_id`.
    # For web apps, read it from the initiating browser's session, never from callback parameters
    # or the state-token lookup. It is checked before exchanging the authorization code.
    # Remove the browser's pending-session association after this method succeeds.
    #
    # @param code [String] authorization code from the callback
    # @param state [String] state token from the callback
    # @param iss [String] issuer URL from the callback
    # @param expected_session_id [String] pending session ID retained by the caller when authorization started
    #
    # @return [Hash{Symbol => String, Integer, nil}] tokens and authenticated session details
    # @raise [CallbackError] if the expected session ID is invalid, state is unknown, or session/issuer validation fails
    # @raise [TokenError] if token exchange or response validation fails
    # @raise [DPoP::Client::Error, PAR::ClientAssertion::Error] if proof/assertion generation fails
    # @raise [HTTPClient::HTTPError, HTTPClient::SSRFError] if token transport fails
    # @raise [State::SessionError] if token subject conflicts with the session DID
    # @raise [ArgumentError] if returned token fields fail token-set validation
    # @raise [Storage::StorageError] if session storage or locking fails
    # @raise [Encryption::EncryptionError] if tokens cannot be encrypted for storage
    #
    def handle_callback(code:, state:, iss:, expected_session_id:)
      unless expected_session_id.is_a?(String) && !expected_session_id.empty?
        raise CallbackError, "Expected session ID is required"
      end

      session = session_manager.get_session_by_state_token(state)

      raise CallbackError, "Invalid state parameter" unless session
      raise CallbackError, "Session ID mismatch" unless session.session_id == expected_session_id
      raise CallbackError, "Issuer mismatch" unless session.auth_server && session.auth_server.issuer == iss

      AuthProto.storage.with_lock(Storage::KeyBuilder.lock_key("session", session.session_id), ttl: 30) do
        response = exchange_code(code: code, session: session)

        token_set = State::TokenSet.new(
          access_token: response['access_token'],
          token_type: response['token_type'],
          expires_in: response['expires_in'],
          refresh_token: response['refresh_token'],
          scope: response['scope'],
          sub: response['sub']
        )

        session.tokens = token_set
        session_manager.complete_authorization(session)

        session.session_data
      end
    end

    # Reads tokens for a session with a currently valid access token.
    #
    # The result contains `:access_token` (String), `:token_type` (String, `DPoP`),
    # `:expires_in` (Integer seconds remaining), `:refresh_token` (String or nil),
    # and `:scope` (String).
    # It also contains `:session_id` (String) and `:did` (String).
    # This method does not refresh expired tokens.
    #
    # @param session_id [String] session identifier
    # @return [Hash{Symbol => String, Integer, nil}, nil] token details, or `nil` for missing/unauthorized sessions
    #
    def get_tokens(session_id)
      session = session_manager.get_session(session_id)
      return nil unless session && session.tokens_valid?

      session.session_data
    end

    # Refreshes a renewable session and persists the replacement tokens.
    #
    # The result contains `:access_token` (String), `:token_type` (String, `DPoP`),
    # `:expires_in` (Integer seconds remaining), `:refresh_token` (String or nil),
    # and `:scope` (String).
    # The result also contains `:session_id` (String) and `:did` (String). An expired access token can
    # still be refreshed when the stored session has a refresh token.
    #
    # @param session_id [String] session to refresh
    # @return [Hash{Symbol => String, Integer, nil}] replacement tokens and session identifiers
    # @raise [TokenError] if the session is missing or has no refresh token
    # @raise [Token::RefreshError] if token refresh fails or exhausts retries
    # @raise [DPoP::Client::Error] if a refresh response lacks a valid nonce
    # @raise [State::SessionError] if replacement tokens have a different subject
    # @raise [Storage::StorageError] if session storage or locking fails
    # @raise [Encryption::EncryptionError] if replacement tokens cannot be stored
    #
    def refresh_token(session_id)
      session = session_manager.get_session(session_id)

      raise TokenError, "Invalid session" unless session
      raise TokenError, "Session not authorized" unless session.renewable?

      AuthProto.storage.with_lock(Storage::KeyBuilder.lock_key("session", session.session_id), ttl: 30) do
        refresher = Token::Refresh.new(
          session: session,
          dpop_client: @dpop_client,
          auth_server: session.auth_server,
          client_metadata: @client_metadata,
          signing_key: @signing_key
        )

        new_tokens = refresher.perform_refresh

        session.tokens = new_tokens
        session_manager.update_session(session)

        session.session_data
      end
    end

    # Checks if a session has valid tokens
    #
    # @param session_id [String] ID of session to check
    # @return [Boolean] true if session exists and has valid tokens
    #
    def authorized?(session_id)
      session = session_manager.get_session(session_id)
      session ? session.tokens_valid? : false
    end

    # Builds authorization headers and a fresh DPoP proof for one HTTP request.
    #
    # The caller sends the request. This method does not refresh tokens, send HTTP,
    # or retry nonce challenges. Feed each full HTTP response to {DPoP::Client#process_response}
    # and call {#refresh_token} explicitly when needed. Generate new headers for each retry.
    #
    # @param session_id [String] authorized session ID
    # @param method [String] HTTP method for the proof
    # @param url [String] absolute request URL without a query string or fragment
    #
    # @return [Hash{String => String}] `Authorization: DPoP ...` and `DPoP` proof headers
    # @raise [TokenError] if the session is missing or its access token is expired
    # @raise [DPoP::Client::Error] if proof generation or nonce lookup fails
    #
    def auth_headers(session_id:, method:, url:)
      session = session_manager.get_session(session_id)

      raise TokenError, "Invalid session" unless session
      raise TokenError, "Session not authorized" if session.pending?
      raise TokenError, "Session has expired" unless session.tokens_valid?

      dpop_proof = dpop_client.generate_proof(
        session: session,
        method: method,
        uri: url,
        access_token: session.tokens.access_token
      )

      {
        "Authorization" => "DPoP #{session.tokens.access_token}",
        "DPoP" => dpop_proof
      }
    end

    # Removes a stored session and its state-token lookup.
    #
    # @param session_id [String] session identifier
    # @return [void]
    # @raise [Storage::StorageError] if deletion or locking fails
    #
    def delete_session(session_id)
      session_manager.delete_session(session_id)
    end

    # Invokes the session manager's expiry cleanup hook.
    #
    # Currently a no-op; expiry is checked during retrieval and by storage TTLs.
    #
    # @return [void]
    #
    def cleanup_expired_sessions
      session_manager.cleanup_expired
    end


    private

    def load_client_metadata(metadata)
      if metadata
        Metadata::ClientMetadata.new(metadata)
      else
        Metadata::ClientMetadata.from_url(@client_id)
      end
    end

    def validate_redirect_uri
      unless @client_metadata.redirect_uris.include?(@redirect_uri)
        raise Error, "redirect_uri not found in client metadata"
      end
    end

    def initialize_signing_key(key)
      if @client_metadata.confidential?
        raise InvalidClientMetadata, "Confidential clients require a signing_key" if key.nil?
      else
        raise InvalidClientMetadata, "Public clients must not supply a signing_key" unless key.nil?
        return nil
      end

      assertion = PAR::ClientAssertion.new(client_id: @client_id, signing_key: key)
      private_key = assertion.signing_key

      if @client_metadata.jwks
        public_key = private_key.to_public.to_map.to_h

        key_in_jwks = @client_metadata.jwks['keys'].any? { |candidate|
          metadata_key_matches_public_key?(candidate, public_key)
        }

        raise InvalidClientMetadata, "signing_key must match an active public key advertised in jwks" if !key_in_jwks
      end

      @signing_key = private_key
      @signing_key_kid = private_key.fields.fetch('kid')
    end

    def metadata_key_matches_public_key?(candidate, public_key)
      return false if candidate['revoked']
      return false if candidate.key?('alg') && candidate['alg'] != PAR::ClientAssertion::ALGORITHM
      return false if candidate.key?('use') && candidate['use'] != 'sig'
      return false if candidate.key?('key_ops') && !candidate['key_ops'].include?('verify')

      %w[kid kty crv x y].all? { |field| candidate[field] == public_key[field] }
    end

    def validate_auth_params(handle, pds, scope)
      unless scope.is_a?(String) && scope.valid_encoding? && Metadata::ClientMetadata::SCOPE_PATTERN.match?(scope)
        raise Error, "scope must contain valid tokens separated by single spaces"
      end

      requested_scopes = scope.split(' ')
      raise Error, "scope must include 'atproto'" unless requested_scopes.include?('atproto')

      undeclared_scopes = requested_scopes - @client_metadata.scope.split(' ')

      unless undeclared_scopes.empty?
        raise Error, "scope contains values not declared in client metadata: #{undeclared_scopes.join(' ')}"
      end

      raise Error, "handle or pds must be provided" if handle.nil? && pds.nil?
      raise Error, "cannot provide both handle and pds" if handle && pds
    end

    def resolve_auth_server_info(pds)
      resource_server = Metadata::ResourceServer.from_url(pds)
      auth_server_url = resource_server.authorization_server

      Metadata::AuthorizationServer.from_url(auth_server_url)
    end

    def submit_authorization_par(authorization_server, session, login_hint: nil)
      par_client = PAR::Client.new(
        authorization_server: authorization_server,
        dpop_client: @dpop_client
      )

      par_request = PAR::Request.build do |req|
        req.client_id = @client_id
        req.redirect_uri = @redirect_uri
        req.state = session.state_token
        req.scope = session.scope
        req.login_hint = login_hint if login_hint
        req.code_challenge = session.pkce_challenge

        if @client_metadata.confidential?
          req.client_assertion = PAR::ClientAssertion.new(client_id: @client_id, signing_key: @signing_key)
        end
      end

      par_response = par_client.submit(par_request, session: session)

      par_client.build_authorization_url(
        request_uri: par_response.request_uri,
        client_id: @client_id
      )
    end

    def exchange_code(code:, session:)
      response = dpop_client.with_nonce_handling(session, session.auth_server.token_endpoint) do
        make_token_request(code, session)
      end

      raise TokenError, "Token request failed: #{response[:status]}" unless response[:status] == 200

      begin
        data = JSON.parse(response[:body])
      rescue JSON::ParserError => e
        raise TokenError, "Invalid token response: #{e.message}"
      end

      validate_token_response(data, session)

      data
    end

    def make_token_request(code, session)
      dpop_proof = dpop_client.generate_proof(
        session: session,
        method: 'POST',
        uri: session.auth_server.token_endpoint
      )

      body = {
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: @redirect_uri,
        client_id: @client_id,
        code_verifier: session.pkce_verifier
      }

      if @client_metadata.confidential?
        assertion = PAR::ClientAssertion.new(
          client_id: @client_id,
          signing_key: @signing_key
        )

        body.merge!(
          client_assertion_type: PAR::CLIENT_ASSERTION_TYPE,
          client_assertion: assertion.generate_jwt(audience: session.auth_server.issuer)
        )
      end

      AuthProto.configuration.http_client.post(
        session.auth_server.token_endpoint,
        body: body,
        headers: {
          "Content-Type" => "application/x-www-form-urlencoded",
          "DPoP" => dpop_proof
        }
      )
    end

    def validate_token_response(response, session)
      ['access_token', 'token_type', 'expires_in', 'scope', 'sub'].each do |field|
        raise TokenError, "Missing #{field} in token response" unless response[field]
      end

      unless response['token_type'].is_a?(String) && response['token_type'].casecmp?('DPoP')
        raise TokenError, "Invalid token_type: #{response['token_type']}"
      end

      raise TokenError, "Missing atproto scope in token response" unless response['scope'].split.include?('atproto')

      # If we have a pre-resolved DID, verify that it matches
      raise TokenError, "Subject mismatch in token response" if session.did && session.did != response['sub']
    end
  end
end
