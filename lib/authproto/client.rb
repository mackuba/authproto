# frozen_string_literal: true

require 'didkit/did'
require 'jose'
require 'json'
require 'uri'

require_relative 'client_metadata'
require_relative 'configuration'
require_relative 'dpop/client'
require_relative 'dpop/key_manager'
require_relative 'errors'
require_relative 'par'
require_relative 'par/client'
require_relative 'par/client_assertion'
require_relative 'par/request'
require_relative 'server_metadata/authorization_server'
require_relative 'server_metadata/resource_server'
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
    # @return [ClientMetadata]
    attr_reader :client_metadata

    # Manager for stored OAuth sessions.
    # @return [State::SessionManager]
    attr_reader :session_manager

    # DPoP key, proof and nonce manager.
    # @return [DPoP::Client]
    attr_reader :dpop_client

    # Creates an OAuth client with its own DPoP key and session manager.
    #
    # Configure {AuthProto.configure} with an HTTP transport before fetching metadata
    # or starting authorization. Reuse `dpop_key` when restoring tokens bound to that key.
    #
    # @param client_id [String] OAuth client ID URL
    # @param redirect_uri [String] callback URI listed in `redirect_uris`
    # @param metadata [Hash{String => Object}, nil] preloaded metadata, or `nil` to fetch `client_id`
    # @param signing_key [Hash, JOSE::JWK, nil] private ES256 client-authentication key, separate from public metadata
    # @param dpop_key [Hash{String => Object}, nil] existing private DPoP JWK, or `nil` to generate one
    #
    # @raise [InvalidClientMetadata] if client metadata is invalid or unavailable
    # @raise [Error] if the redirect URI is not registered
    # @raise [DPoP::KeyManager::KeyError] if the DPoP key cannot be imported or generated
    # @raise [HTTPClient::HTTPError, HTTPClient::SSRFError] if fetching client metadata fails
    #
    def initialize(client_id:, redirect_uri:, metadata: nil, dpop_key: nil, signing_key: nil)
      @client_id = client_id
      @redirect_uri = redirect_uri

      # Initialize core dependencies
      @client_metadata = load_client_metadata(metadata)
      validate_redirect_uri
      @signing_key = initialize_signing_key(signing_key)

      @session_manager = State::SessionManager.new
      @dpop_client = initialize_dpop(dpop_key)
    end

    # Starts authorization, stores a pending session, and submits a PAR request.
    #
    # Supply exactly one of `handle` or `pds_url`. Open the returned `:url` in a browser
    # and pass the eventual callback parameters to {#handle_callback}.
    #
    # @param handle [String, nil] account handle (optionally prefixed with `@`) or DID
    # @param pds_url [String, nil] PDS URL when no handle is supplied
    # @param scope [String] space-separated scopes, including `atproto`
    #
    # @return [Hash{Symbol => String}] `:url` is the browser URL; `:session_id` identifies the pending session
    # @raise [Error] if identity arguments or scope are invalid, the handle cannot be verified, or no HTTPS PDS is found
    # @raise [DIDKit::DIDError, DIDKit::FormatError, DIDKit::APIError] if DID validation or document fetching fails
    # @raise [InvalidAuthorizationServer] if server discovery or metadata validation fails
    # @raise [PAR::Error] if the pushed authorization request fails
    # @raise [PAR::ClientAssertion::Error] if confidential-client signing fails
    # @raise [DPoP::Client::Error] if generating the PAR proof fails
    # @raise [HTTPClient::SSRFError] if server discovery rejects a destination
    # @raise [Storage::StorageError] if session storage or locking fails
    # @raise [Encryption::EncryptionError] if session serialization cannot encrypt secrets
    #
    def authorize(handle: nil, pds_url: nil, scope: "atproto")
      validate_auth_params(handle, pds_url, scope)

      # Create new session
      session = session_manager.create_session(
        client_id: client_id,
        scope: scope
      )

      # Store session with storage backend
      session_manager.update_session(session)

      # Resolve identity and authorization server if handle provided
      if handle
        auth_info = resolve_from_handle(handle, session)
      elsif pds_url
        auth_info = resolve_from_pds(pds_url, session)
      else
        raise Error, "Either handle or pds_url must be provided"
      end

      # Generate authorization URL
      auth_url = generate_authorization_url(
        auth_info[:server],
        session,
        login_hint: handle
      )

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
    # @param code [String] authorization code from the callback
    # @param state [String] state token from the callback
    # @param iss [String] issuer URL from the callback
    #
    # @return [Hash{Symbol => String, Integer, nil}] tokens and authenticated session details
    # @raise [CallbackError] if state is unknown or the issuer does not match the session
    # @raise [TokenError] if token exchange or response validation fails
    # @raise [DPoP::Client::Error, PAR::ClientAssertion::Error] if proof/assertion generation fails
    # @raise [HTTPClient::HTTPError, HTTPClient::SSRFError] if token transport fails
    # @raise [State::SessionError] if token subject conflicts with the session DID
    # @raise [ArgumentError] if returned token fields fail token-set validation
    # @raise [Storage::StorageError] if session storage or locking fails
    # @raise [Encryption::EncryptionError] if tokens cannot be encrypted for storage
    #
    def handle_callback(code:, state:, iss:)
      # Find and validate session
      session = session_manager.get_session_by_state(state)
      raise CallbackError, "Invalid state parameter" unless session

      # Verify issuer matches session
      raise CallbackError, "Issuer mismatch" unless session.auth_server && session.auth_server.issuer == iss

      AuthProto.storage.with_lock(Storage::KeyBuilder.lock_key("session", session.session_id), ttl: 30) do
        # Exchange code for tokens
        token_response = exchange_code(
          code: code,
          session: session
        )

        # Validate token response
        validate_token_response(token_response, session)

        # Create token set and store in session
        token_set = State::TokenSet.new(
          access_token: token_response["access_token"],
          token_type: token_response["token_type"],
          expires_in: token_response["expires_in"],
          refresh_token: token_response["refresh_token"],
          scope: token_response["scope"],
          sub: token_response["sub"]
        )
        session.tokens = token_set

        # Update stored session
        session_manager.update_session(session)

        {
          access_token: token_set.access_token,
          token_type: token_set.token_type,
          expires_in: (token_set.expires_at - Time.now).to_i,
          refresh_token: token_set.refresh_token,
          scope: token_set.scope,
          session_id: session.session_id,
          did: session.did
        }
      end
    end

    # Reads tokens for a session with a currently valid access token.
    #
    # The result contains `:access_token` (String), `:token_type` (String, `DPoP`),
    # `:expires_in` (Integer seconds remaining), `:refresh_token` (String or nil),
    # and `:scope` (String).
    # This method does not refresh expired tokens.
    #
    # @param session_id [String] session identifier
    # @return [Hash{Symbol => String, Integer, nil}, nil] token details, or `nil` for missing/unauthorized sessions
    #
    def get_tokens(session_id)
      session = session_manager.get_session(session_id)
      return nil unless session&.authorized?

      {
        access_token: session.tokens.access_token,
        token_type: session.tokens.token_type,
        expires_in: (session.tokens.expires_at - Time.now).to_i,
        refresh_token: session.tokens.refresh_token,
        scope: session.tokens.scope
      }
    end

    # Refreshes a renewable session and persists the replacement tokens.
    #
    # The result contains `:access_token` (String), `:token_type` (String, `DPoP`),
    # `:expires_in` (Integer seconds remaining), `:refresh_token` (String or nil),
    # and `:scope` (String).
    # The result also contains `:session_id` (String). An expired access token can
    # still be refreshed when the stored session has a refresh token.
    #
    # @param session_id [String] session to refresh
    # @return [Hash{Symbol => String, Integer, nil}] replacement tokens and session ID
    # @raise [TokenError] if the session is missing or has no refresh token
    # @raise [Token::RefreshError] if token refresh fails or exhausts retries
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
          client_metadata: client_metadata,
          signing_key: @signing_key
        )

        new_tokens = refresher.perform
        session.tokens = new_tokens

        # Update stored session
        session_manager.update_session(session)

        {
          access_token: new_tokens.access_token,
          token_type: new_tokens.token_type,
          expires_in: (new_tokens.expires_at - Time.now).to_i,
          refresh_token: new_tokens.refresh_token,
          scope: new_tokens.scope,
          session_id: session.session_id
        }
      end
    end

    # Checks if a session has valid tokens
    #
    # @param session_id [String] ID of session to check
    # @return [Boolean] true if session exists and has valid tokens
    #
    def authorized?(session_id)
      session = session_manager.get_session(session_id)
      session&.authorized? || false
    end

    # Builds authorization headers and a fresh DPoP proof for one HTTP request.
    #
    # The caller sends the request. This method does not refresh tokens, send HTTP,
    # or retry nonce challenges. Feed response headers to {DPoP::Client#process_response}
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
      raise TokenError, "Session not authorized" unless session.authorized?

      # Generate DPoP proof
      proof = dpop_client.generate_proof(
        http_method: method,
        http_uri: url,
        access_token: session.tokens.access_token
      )

      {
        "Authorization" => "DPoP #{session.tokens.access_token}",
        "DPoP" => proof
      }
    end

    # Removes a stored session and its state-token lookup.
    #
    # @param session_id [String] session identifier
    # @return [void]
    # @raise [Storage::StorageError] if deletion or locking fails
    #
    def remove_session(session_id)
      key = Storage::KeyBuilder.session_key(session_id)
      AuthProto.storage.delete(key)
      session_manager.remove_session(session_id)
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
        ClientMetadata.new(metadata)
      else
        ClientMetadata.from_url(@client_id)
      end
    end

    def validate_redirect_uri
      valid = @client_metadata.redirect_uris.include?(@redirect_uri)
      raise Error, "redirect_uri not found in client metadata" unless valid
    end

    def initialize_signing_key(key)
      if client_metadata.confidential?
        raise InvalidClientMetadata, "Confidential clients require a signing_key" if key.nil?
      else
        raise InvalidClientMetadata, "Public clients must not supply a signing_key" unless key.nil?
        return nil
      end

      assertion = PAR::ClientAssertion.new(client_id: client_id, signing_key: key)
      private_key = assertion.signing_key

      if client_metadata.jwks
        public_key = private_key.to_public.to_map.to_h

        key_in_jwks = client_metadata.jwks['keys'].any? { |candidate|
          !candidate['revoked'] &&
            (!candidate.key?('alg') || candidate['alg'] == 'ES256') &&
            (!candidate.key?('use') || candidate['use'] == 'sig') &&
            (!candidate.key?('key_ops') || candidate['key_ops'].include?('verify')) &&
            %w[kid kty crv x y].all? { |field| candidate[field] == public_key[field] }
        }

        unless key_in_jwks
          raise InvalidClientMetadata, "signing_key must match an active public key advertised in jwks"
        end
      end

      private_key
    end

    def initialize_dpop(key)
      key_manager = if key
                      DPoP::KeyManager.from_jwk(key)
                    else
                      DPoP::KeyManager.new
                    end

      DPoP::Client.new(key_manager: key_manager)
    end

    def validate_auth_params(handle, pds_url, scope)
      raise Error, "scope must include 'atproto'" unless scope.split.include?("atproto")
      raise Error, "handle or pds_url must be provided" if handle.nil? && pds_url.nil?
      raise Error, "cannot provide both handle and pds_url" if handle && pds_url
    end

    def resolve_from_handle(handle, session)
      did = DIDKit::DID.resolve_handle(handle)
      raise Error, "Could not resolve or verify identity #{handle}" unless did

      pds_url = did.document.pds_endpoint
      raise Error, "No HTTPS PDS location found for #{did}" unless pds_url && URI(pds_url).is_a?(URI::HTTPS)

      session.did = did.to_s

      # Get authorization server from PDS
      server = resolve_auth_server(pds_url)
      session.authorization_server = server

      # Update stored session
      session_manager.update_session(session)

      { server: server, pds: pds_url }
    end

    def resolve_from_pds(pds_url, session)
      # Get authorization server from PDS
      server = resolve_auth_server(pds_url)
      session.authorization_server = server

      # Update stored session
      session_manager.update_session(session)

      { server: server, pds: pds_url }
    end

    def resolve_auth_server(pds_url)
      # Get resource server metadata
      resource_server = ServerMetadata::ResourceServer.from_url(pds_url)
      auth_server_url = resource_server.authorization_servers.first

      # Get and validate authorization server metadata
      ServerMetadata::AuthorizationServer.from_issuer(auth_server_url)
    end

    def generate_authorization_url(auth_server, session, login_hint: nil)
      # Create PAR client
      par_client = PAR::Client.new(
        endpoint: auth_server.pushed_authorization_request_endpoint,
        dpop_client: @dpop_client
      )

      # Build PAR request
      par_request = PAR::Request.build do |config|
        config.client_id = client_id
        config.redirect_uri = redirect_uri
        config.state = session.state_token
        config.scope = session.scope
        config.login_hint = login_hint if login_hint

        # Add PKCE parameters
        config.code_challenge = session.pkce_challenge
        config.code_challenge_method = "S256"

        # Public clients use PKCE and DPoP without client authentication.
        if client_metadata.confidential?
          client_assertion = PAR::ClientAssertion.new(client_id: client_id, signing_key: @signing_key)
          config.client_assertion = client_assertion.generate_jwt(audience: auth_server.issuer)
          config.client_assertion_type = PAR::CLIENT_ASSERTION_TYPE
        end

        # Add DPoP proof
        proof = @dpop_client.generate_proof(
          http_method: "POST",
          http_uri: auth_server.pushed_authorization_request_endpoint
        )
        config.dpop_proof = proof
      end

      # Submit PAR request
      response = par_client.submit(par_request)

      # Build final authorization URL
      par_client.authorization_url(
        authorize_endpoint: auth_server.authorization_endpoint,
        request_uri: response.request_uri,
        client_id: client_id
      )
    end

    def exchange_code(code:, session:)
      # Initial token request without nonce
      response = make_token_request(code, session)

      # Handle DPoP nonce requirement
      if requires_dpop_nonce?(response)
        # Extract and store nonce from error response
        extract_dpop_nonce(response)
        dpop_client.process_response(response[:headers], session.auth_server.issuer)

        # Retry request with nonce
        response = make_token_request(code, session)
      end

      raise TokenError, "Token request failed: #{response[:status]}" unless response[:status] == 200

      begin
        JSON.parse(response[:body])
      rescue JSON::ParserError => e
        raise TokenError, "Invalid token response: #{e.message}"
      end
    end

    def make_token_request(code, session)
      # Generate proof
      proof = dpop_client.generate_proof(
        http_method: "POST",
        http_uri: session.auth_server.token_endpoint
      )

      body = {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirect_uri,
        client_id: client_id,
        code_verifier: session.pkce_verifier
      }

      # Add client authentication
      if client_metadata.confidential?
        client_assertion = PAR::ClientAssertion.new(
          client_id: client_id,
          signing_key: @signing_key
        )

        body.merge!(
          client_assertion_type: PAR::CLIENT_ASSERTION_TYPE,
          client_assertion: client_assertion.generate_jwt(
            audience: session.auth_server.issuer
          )
        )
      end

      AuthProto.configuration.http_client.post(
        session.auth_server.token_endpoint,
        body: body,
        headers: {
          "Content-Type" => "application/x-www-form-urlencoded",
          "DPoP" => proof
        }
      )
    end

    def requires_dpop_nonce?(response)
      return false unless response[:status] == 400

      error_data = JSON.parse(response[:body])
      error_data["error"] == "use_dpop_nonce"
    rescue JSON::ParserError
      false
    end

    def extract_dpop_nonce(response)
      headers = response[:headers]
      nonce = headers["DPoP-Nonce"] ||
              headers["dpop-nonce"] ||
              headers["Dpop-Nonce"]

      raise TokenError, "No DPoP nonce provided in error response" unless nonce

      nonce
    end

    def validate_token_response(response, session)
      # Required fields
      %w[access_token token_type expires_in scope sub].each do |field|
        raise TokenError, "Missing #{field} in token response" unless response[field]
      end

      # Token type must be DPoP
      raise TokenError, "Invalid token_type: #{response["token_type"]}" unless response["token_type"] == "DPoP"

      # Scope must include atproto
      raise TokenError, "Missing atproto scope in token response" unless response["scope"].split.include?("atproto")

      # If we have a pre-resolved DID, verify it matches
      raise TokenError, "Subject mismatch in token response" if session.did && session.did != response["sub"]

      # Process DPoP-Nonce from response headers if present
      return unless response[:headers] && response[:headers]["DPoP-Nonce"]

      dpop_client.process_response(
        response[:headers],
        session.auth_server.issuer
      )
    end
  end
end
