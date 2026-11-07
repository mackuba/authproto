# frozen_string_literal: true

require 'didkit/did'
require 'jose'
require 'uri'

require_relative 'configuration'
require_relative 'dpop/client'
require_relative 'errors'
require_relative 'http_helpers'
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
require_relative 'token/identity'
require_relative 'token/refresh'
require_relative 'token/response'
require_relative 'token/revocation'

module AuthProto

  #
  # The main client class of AuthProto for authorizing and managing user sessions and making required OAuth requests.
  #
  # This class is the main entry point to the library, and a wrapper for most of the functionality in the other
  # classes. It handles or manages:
  #
  # - loading and validating client metadata and resource and authorization server metadata
  # - initial session authorization and generating an authorization URL
  # - executing PAR requests
  # - completing an authorization on an OAuth callback
  # - refreshing sessions
  # - generating authorization headers for data requests to the resource server (PDS)
  # - handling DPoP and nonces
  # - generating client assertions
  # - deleting and revoking sessions
  #
  # A {Client} is configured for a specific Client ID and a specific redirect URI as a callback, but is not bound
  # to any single user session. Session IDs are passed in the arguments to specific method calls.
  #
  # @example
  #   client = AuthProto::Client.new(
  #     client_id: "https://site.example.com/oauth-client-metadata.json",
  #     redirect_uri: "https://site.example.com/callback"
  #   )
  #   
  #   auth = client.authorize(
  #     pds: 'https://pds.example.com',
  #     scope: 'atproto rpc:app.bsky.feed.getTimeline?aud=*'
  #   )
  #   
  #   p auth[:url]
  #   
  #   # ...
  #   
  #   client.handle_callback(params, expected_session_id: auth[:session_id])
  #   
  #   url = "https://pds.example.com/xrpc/app.bsky.feed.getTimeline"
  #   
  #   response = client.with_nonce_handling(auth[:session_id], url) do
  #     headers = client.auth_headers(session_id: auth[:session_id], method: 'GET', url: url)
  #     response = Net::HTTP.get_response(URI(url), headers)
  #   
  #     {
  #       status: response.code,
  #       headers: response.to_hash,
  #       body: response.body
  #     }
  #   end
  #

  class Client
    include HTTPHelpers
    include Token::Identity

    # An error raised when initial authorization fails.
    class AuthorizationError < AuthProto::Error; end

    #
    # An error raised when authorization callback validation or authorization fails.
    #

    class CallbackError < AuthProto::Error

      # OAuth error code returned by the authorization server, if included.
      # @return [String, nil]
      attr_reader :error_code

      # Human-readable explanation returned by the authorization server, if included.
      # @return [String, nil]
      attr_reader :error_description

      # URL with more information about the OAuth error, if included.
      # @return [String, nil]
      attr_reader :error_uri

      # Creates a callback error with optional OAuth error details.
      #
      # @param message [String] explanation of the callback failure
      # @param error_code [String, nil] `error` value from the callback URL params
      # @param error_description [String, nil] `error_description` value from the callback URL params
      # @param error_uri [String, nil] `error_uri` value from the callback URL params
      #
      def initialize(message, error_code: nil, error_description: nil, error_uri: nil)
        @error_code = error_code
        @error_description = error_description
        @error_uri = error_uri

        super(message)
      end
    end

    # An error raised when token operations fail.
    class TokenError < AuthProto::Error; end

    #
    # An error raised when session operations fail.
    #

    class SessionError < AuthProto::Error

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

    # OAuth client ID URL
    # @return [String]
    attr_reader :client_id

    # The callback URL to which the user is redirected to complete authorization
    # @return [String]
    attr_reader :redirect_uri

    # Parsed and validated metadata about the client
    # @return [Metadata::ClientMetadata]
    attr_reader :client_metadata

    # A helper object managing stored OAuth sessions
    # @return [State::SessionManager]
    attr_reader :session_manager

    # A helper object generating DPoP proofs and handling DPoP nonces for the Client
    # @return [DPoP::Client]
    attr_reader :dpop_client


    # Checks whether a client ID uses the localhost development URL prefix.
    #
    # For apps with a localhost client ID, use the {Client.for_localhost} helper to create an instance of {Client}.
    #
    # @param client_id [String] OAuth client ID URL
    # @return [Boolean] whether the URL starts with `http://localhost`, optionally followed by `/` or `?`
    #
    def self.localhost_app?(client_id)
      client_id.is_a?(String) && %r{\Ahttp://localhost(?:[/?]|\z)}i.match?(client_id)
    end


    # Creates a localhost development client with redirect URI and scope encoded in its client ID.
    #
    # @param redirect_uri [String, URI::Generic] loopback callback URL used to complete authorization
    # @param scope [String] space-separated scopes to declare in the generated client metadata
    # @return [Client] configured localhost client
    # @raise [InvalidClientMetadata] if the redirect URI or scope is invalid
    #
    def self.for_localhost(redirect_uri:, scope: 'atproto')
      query = URI.encode_www_form(redirect_uri: redirect_uri, scope: scope)

      self.new(client_id: "http://localhost/?#{query}", redirect_uri: redirect_uri)
    end


    # Creates an OAuth client with specified configuration.
    #
    # The initializer validates all passed arguments, fetches and validates the remote metadata JSON if not provided
    # inline, and prepares helper objects necessary later.
    #
    # For localhost development:
    # - pass `client_id` of `http://localhost/` with `redirect_uri` and `scope` encoded as query parameters
    # - pass `redirect_uri` on `127.0.0.1` or `[::1]` hostname (optionally with port)
    # - do not pass `metadata` or `signing_key`
    #
    # @param client_id [String] the OAuth client ID URL
    # @param redirect_uri [String, URI::Generic] the callback URL to which the user is redirected to complete
    #   authorization; must be included on the `redirect_uris` list in the metadata
    # @param metadata [Hash{String => Object}, nil] optionally, the client metadata JSON located at the client ID URL;
    #   if not included, it will be fetched from that URL during initialization
    # @param signing_key [Hash, JOSE::JWK, nil] a private ES256 key for client authentication (client assertions)
    #   for confidential clients
    #
    # @raise [InvalidClientMetadata] if the metadata or some other parameters are invalid or don't match each other
    # @raise [PAR::ClientAssertion::Error] if the signing key is invalid or not usable
    # @raise [HTTPClient::HTTPError, HTTPClient::SSRFError] if fetching client metadata fails
    #
    def initialize(client_id:, redirect_uri:, metadata: nil, signing_key: nil)
      @client_id = client_id
      @redirect_uri = redirect_uri.is_a?(URI::Generic) ? redirect_uri.to_s : redirect_uri

      if metadata && self.class.localhost_app?(client_id)
        raise InvalidClientMetadata.new(
          "For localhost clients, do not include metadata as a hash, " +
          "but configure scope and redirect_uri through the client ID query params"
        )
      end

      if metadata && metadata['client_id'] != @client_id
        raise InvalidClientMetadata, "client_id mismatch: #{metadata['client_id']} != #{@client_id}"
      end

      # Client metadata is fetched from the client ID URL if not provided directly
      @client_metadata = load_client_metadata(metadata)

      validate_redirect_uri
      initialize_client_assertion(signing_key)

      signing_keys = @client_assertion ? { @signing_key_kid => @signing_key_thumbprint } : {}
      @session_manager = State::SessionManager.new(client_id: @client_id, supported_signing_keys: signing_keys)

      @dpop_client = DPoP::Client.new
    end


    # Starts the authorization process, creates a pending session, and submits a PAR request, then generates an
    # authorization URL that the user should log in on.
    #
    # Requires either a `handle` or a `pds` argument, but not both at the same time. If `handle` is passed, the user's
    # PDS is looked up from the DID document and the user is directed there with a "login hint"; otherwise, the
    # authorization begins on the given PDS, but without a pre-selected account.
    #
    # Returns a hash containing a `:url` and a `:session_id`. Direct the user to the returned authorization URL,
    # and store the session ID in a local context or a browser session, since it will be needed to complete
    # authorization at the callback endpoint.
    #
    # @param handle [String, nil] account handle (may be prefixed with a `@`) or a DID string
    # @param pds [String, URI::HTTPS, nil] full URL of the PDS to authorize the user on
    # @param scope [String] space-separated list of scopes to request authorization for; the scopes must all be
    #   declared in the client metadata, and must include `atproto`
    #
    # @return [Hash{Symbol => String}] `:url` to direct the user to, `:session_id` of the created session
    #
    # @raise [AuthorizationError] if identity arguments or scope are invalid or identity can't be resolved
    # @raise [DIDKit::DIDError, DIDKit::FormatError, DIDKit::APIError] if DID validation or document fetching fails
    # @raise [Encryption::EncryptionError] if session serialization cannot encrypt secrets
    # @raise [HTTPClient::SSRFError] if server discovery rejects a destination
    # @raise [InvalidAuthorizationServer] if server discovery or metadata validation fails
    # @raise [DPoP::Client::Error] if generating the PAR proof fails
    # @raise [DPoP::KeySet::KeyError] if generating the session key fails
    # @raise [PAR::ClientAssertion::Error] if client assertion signing fails
    # @raise [PAR::Error] if the pushed authorization request fails
    # @raise [Storage::StorageError] if session storage or locking fails
    #
    def authorize(handle: nil, pds: nil, scope: 'atproto')
      validate_auth_params(handle, pds, scope)
      pds = pds.to_s if pds.is_a?(URI::HTTP)

      if !pds
        did = DIDKit::DID.resolve_handle(handle)
        raise AuthorizationError, "Could not resolve or verify identity #{handle}" unless did

        pds = did.document.pds_endpoint
        raise AuthorizationError, "No HTTPS PDS location found for #{did}" unless pds && URI(pds).is_a?(URI::HTTPS)
      end

      authorization_server = resolve_auth_server_info(pds)

      session = session_manager.create_session(
        client_id: @client_id,
        scope: scope,
        auth_server: authorization_server,
        did: did&.to_s,
        pds: pds,
        signing_key_id: @signing_key_kid
      )

      auth_url = submit_authorization_par(authorization_server, session, login_hint: handle)

      {
        url: auth_url,
        session_id: session.session_id
      }
    end


    # Validates received callback parameters, exchanges the code for access tokens, and stores the
    # authenticated session.
    #
    # Call this method from the callback endpoint to which the user is redirected after authorizing access for your
    # app on their PDS. The callback should include `:code`, `:state` and `:iss` params, which you need to pass here
    # (unless the authorization was denied or otherwise failed, in which case it will include an `:error` param).
    #
    # Additionally, you need to provide the `session_id` of the pending session, received earlier in the response
    # from the {#authorize} method. Make sure to confirm that this is the same session that has started the process
    # earlier: take the session ID either from a local context for scripts, or from the initiating browser session for
    # web apps, do not infer it from the received callback parameters.
    #
    # Returns a hash with session data, containing:
    #
    # - `:session_id` (String)
    # - `:did` (String)
    # - `:pds` (String or nil)
    # - `:access_token` (String)
    # - `:refresh_token` (String or nil)
    # - `:expires_in` (Integer) – number of seconds remaining until the access token expires
    # - `:requested_scope` (String) – space-separated list of requested permissions
    # - `:granted_scope` (String) – space-separated list of actually granted permissions
    #
    # @param callback_params [Hash{String, Symbol => Object}] callback query parameters from the URL the user gets
    #    redirected to after authorization (should contain `code`, `state` and `iss`, or `error`)
    # @param expected_session_id [String] pending session ID previously received from {#authorize}
    #
    # @return [Hash{Symbol => String, Integer, nil}] tokens and session data
    #
    # @raise [ArgumentError] if returned token fields fail token-set validation
    # @raise [CallbackError] if parameters are invalid, the server returns an OAuth error, the expected session ID
    #   is invalid, state is unknown, or session/issuer validation fails
    # @raise [DPoP::Client::Error] if proof/assertion generation fails
    # @raise [Encryption::EncryptionError] if tokens cannot be encrypted for storage
    # @raise [HTTPClient::HTTPError, HTTPClient::SSRFError] if token transport fails
    # @raise [PAR::ClientAssertion::Error] if proof/assertion generation fails
    # @raise [State::SessionError] if token subject conflicts with the session DID
    # @raise [Storage::StorageError] if session storage or locking fails
    # @raise [TokenError] if token exchange or response validation fails; identity failures attempt token revocation
    #
    def handle_callback(callback_params, expected_session_id:)
      unless expected_session_id.is_a?(String) && !expected_session_id.empty?
        raise CallbackError, "Expected session ID is required"
      end

      params = validate_callback_params(callback_params)
      code, state, iss = params.values_at('code', 'state', 'iss')
      session = session_manager.get_session_by_state_token(state)

      raise CallbackError, "Invalid state parameter" unless session
      raise CallbackError, "Session ID mismatch" unless session.session_id == expected_session_id
      raise CallbackError, "Issuer mismatch" unless session.auth_server && session.auth_server.issuer == iss

      AuthProto.storage.with_lock(Storage::KeyBuilder.lock_key("session", session.session_id), ttl: 30) do
        token_set = exchange_code(code: code, session: session)

        session.tokens = token_set
        session_manager.complete_authorization(session)

        session.session_data
      end
    end


    # Looks up a session using given ID and returns its tokens and session info.
    #
    # Returns a hash with session data, containing:
    #
    # - `:session_id` (String)
    # - `:did` (String)
    # - `:pds` (String or nil)
    # - `:access_token` (String)
    # - `:refresh_token` (String or nil)
    # - `:expires_in` (Integer) – number of seconds remaining until the access token expires
    # - `:requested_scope` (String) – space-separated list of requested permissions
    # - `:granted_scope` (String) – space-separated list of actually granted permissions
    #
    # Returns nil if a session is not found or its access token is expired.
    #
    # @param session_id [String] session identifier
    # @return [Hash{Symbol => String, Integer, nil}, nil] tokens and session data, or `nil` if not found or expired
    #
    def get_tokens(session_id)
      session = session_manager.get_session(session_id)
      return nil unless session && session.tokens_valid?

      session.session_data
    end


    # Looks up a session using given ID and refreshes its set of tokens.
    #
    # Returns a hash with session data, containing:
    #
    # - `:session_id` (String)
    # - `:did` (String)
    # - `:pds` (String or nil)
    # - `:access_token` (String)
    # - `:refresh_token` (String or nil)
    # - `:expires_in` (Integer) – number of seconds remaining until the access token expires
    # - `:requested_scope` (String) – space-separated list of requested permissions
    # - `:granted_scope` (String) – space-separated list of actually granted permissions
    #
    # @param session_id [String] session to refresh
    # @return [Hash{Symbol => String, Integer, nil}] updated tokens and session data
    #
    # @raise [DPoP::Client::Error] if a refresh response lacks a valid nonce
    # @raise [Encryption::EncryptionError] if replacement tokens cannot be stored
    # @raise [State::SessionError] if replacement tokens have a different subject
    # @raise [Storage::StorageError] if session storage or locking fails
    # @raise [TokenError] if the session is missing or has no refresh token
    # @raise [Token::RefreshError] if the current PDS differs or token refresh fails
    #
    def refresh_token(session_id)
      AuthProto.storage.with_lock(Storage::KeyBuilder.lock_key('session', session_id), ttl: 30) do
        session = session_manager.get_session(session_id)

        raise TokenError, "Invalid session" unless session
        raise TokenError, "Session not authorized" unless session.renewable?

        refresher = Token::Refresh.new(
          session: session,
          dpop_client: @dpop_client,
          auth_server: session.auth_server,
          client_metadata: @client_metadata,
          client_assertion: @client_assertion
        )

        new_tokens = refresher.perform_refresh

        session.tokens = new_tokens
        session_manager.update_session(session)

        session.session_data
      end
    end


    # Returns the global HTTP client configured through `AuthProto.configuration`.
    #
    # @return [#get, #post, nil] configured HTTP client, or `nil` when not configured
    #
    def http
      AuthProto.configuration.http_client
    end


    # Checks if a session with given ID exists and has valid and not expired tokens.
    #
    # @param session_id [String] ID of a session to look up
    # @return [Boolean] true if the session exists, is authenticated, and its access token is not expired
    #
    def authorized?(session_id)
      session = session_manager.get_session(session_id)
      session ? session.tokens_valid? : false
    end


    # Generates required authorization headers for a new HTTP request to user's resource server (PDS).
    #
    # The {Client} does not send the request itself; the headers are returned to the caller so you can add them
    # to a request made using an HTTP client library of your choice.
    #
    # Returns two headers:
    # - `Authorization: DPoP <access_token>`
    # - `DPoP: <dpop_proof>`
    #
    # New set of headers are needed for each new HTTP request, including repeated requests with an updated DPoP nonce
    # or refreshed access token. After the request, the response should be passed to {#process_dpop} so the DPoP
    # handling code can update the stored nonce.
    #
    # @param session_id [String] session ID of an authorized session
    # @param method [String] HTTP method for the proof
    # @param url [String, URI::HTTPS] absolute HTTPS URL of the request; the query string and fragment are ignored
    #
    # @return [Hash{String => String}] headers to attach to an outgoing request
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


    # Updates the stored DPoP server nonce from the `DPoP-Nonce` header returned in the given response.
    #
    # The response is expected to be in a hash format:
    #
    # ```rb
    # {
    #   status: 200,
    #   headers: { ... },  # string keys and values
    #   body: "..."        # string, not parsed JSON
    # }
    # ```
    #
    # @param response [Hash{Symbol => Object}] HTTP response hash with `:status`, `:headers`, and `:body`
    # @param url [String, URI::HTTPS] URL of the request that produced the response (only the origin is used)
    # @param session_id [String] ID of the session that made the request
    # @return [void]
    # @raise [DPoP::Client::Error] if the response or nonce is invalid or storage fails
    #
    def process_dpop(response, url:, session_id:)
      dpop_client.process_response(response, url: url, session_id: session_id)
    end


    # Checks whether an HTTP response indicates that the server has rejected the request, requiring a retry
    # with a new DPoP nonce.
    #
    # The response is expected to be in a hash format:
    #
    # ```rb
    # {
    #   status: 200,
    #   headers: { ... },  # string keys and values
    #   body: "..."        # string, not parsed JSON
    # }
    # ```
    #
    # @param response [Hash{Symbol => Object}] HTTP response hash with `:status`, `:headers`, and `:body`
    # @return [Boolean] if the response is a `use_dpop_nonce` error
    # @raise [DPoP::Client::Error] if the response hash is invalid
    #
    def has_nonce_error?(response)
      dpop_client.has_nonce_error?(response)
    end


    # A helper for making a request with a possible retry with an updated DPoP nonce.
    #
    # Pass a block to this method, which makes a request to the resource or authorization server and returns the
    # received response in a hash format:
    #
    # ```rb
    # {
    #   status: 200,
    #   headers: { ... },  # string keys and values
    #   body: "..."        # string, not parsed JSON
    # }
    # ```
    #
    # The method will run that block, process the headers from the received response, store the returned DPoP nonce,
    # and if the response indicates a `use_dpop_nonce` error, it will call the block again to let you repeat the
    # request with a new nonce. Returns the response from the final request, including if the second attempt returns
    # an error response.
    #
    # @example using with Net::HTTP
    #   uri = URI.join(pds_url, '/xrpc/app.bsky.feed.getTimeline')
    #
    #   response = client.with_nonce_handling(session_id, uri) do
    #     headers = client.auth_headers(session_id: session_id, method: 'GET', url: uri)
    #     response = Net::HTTP.get_response(uri, headers)
    #
    #     {
    #       status: response.code,
    #       headers: response.to_hash,
    #       body: response.body
    #     }
    #   end
    #
    # @example using with AuthProto's HTTPClient
    #   uri = URI.join(pds_url, '/xrpc/app.bsky.feed.getTimeline')
    #
    #   response = client.with_nonce_handling(session_id, uri) do
    #     headers = client.auth_headers(session_id: session_id, method: 'GET', url: uri)
    #
    #     client.http.get(uri, headers)
    #   end
    #
    # @param session_id [String] ID of the session making the request
    # @param url [String, URI::HTTPS] URL of the request (only origin is used)
    # @yield a block that generates fresh authorization headers and send a request with them
    # @yieldreturn [Hash{Symbol => Object}] HTTP response with `:status`, `:headers`, and `:body`
    #
    # @return [Hash{Symbol => Object}] the final response
    # @raise [DPoP::Client::Error] if the response or nonce is invalid or storage fails
    #
    def with_nonce_handling(session_id, url, &block)
      dpop_client.with_nonce_handling(session_id, url, &block)
    end


    # Removes the session's data from the session storage. If `revoke: true` is passed, additionally attempts to
    # revoke the access & refresh tokens on the authorization server first, if a revoke endpoint is available.
    #
    # Does nothing if the session is not found. If the server has no revoke endpoint or the session is not
    # authorized yet, session is only removed from the app's storage. If token revocation is attempted but fails,
    # an error is raised and the session is *not* removed locally (if refresh token is successfully revoked,
    # subsequent access token revocation is allowed to fail).
    #
    # @param session_id [String] session identifier
    # @param revoke [Boolean] revoke the refresh token (if present) and access token before local deletion
    # @return [void]
    #
    # @raise [DPoP::Client::Error, HTTPClient::HTTPError] if revocation proof or transport handling fails
    # @raise [Storage::StorageError] if deletion or locking fails
    # @raise [Token::Revocation::Error] if a required revocation request is rejected
    #
    def delete_session(session_id, revoke: false)
      AuthProto.storage.with_lock(Storage::KeyBuilder.lock_key('session', session_id), ttl: 30) do
        session = session_manager.get_session(session_id)
        return unless session

        if revoke && session.tokens && session.can_be_revoked?
          revocation = Token::Revocation.new(
            session: session,
            dpop_client: @dpop_client,
            client_metadata: @client_metadata,
            client_assertion: @client_assertion
          )

          if session.tokens.refresh_token
            revocation.revoke_token(session.tokens.refresh_token, :token_type => :refresh_token)
            refresh_revoked = true
          end

          begin
            revocation.revoke_token(session.tokens.access_token, :token_type => :access_token)
          rescue StandardError
            raise unless refresh_revoked
          end
        end

        session_manager.delete_session(session_id)
      end
    end


    private

    # --- used in initialize ---

    def load_client_metadata(metadata)
      if metadata
        Metadata::ClientMetadata.new(metadata)
      else
        Metadata::ClientMetadata.from_url(@client_id)
      end
    end

    def validate_redirect_uri
      return if @client_metadata.redirect_uris.include?(@redirect_uri)

      # localhost development exception
      if URI(@client_id).scheme == 'http'
        components = loopback_redirect_components(@redirect_uri)

        if components && @client_metadata.redirect_uris.any? { |uri| loopback_redirect_components(uri) == components }
          return
        end
      end

      raise InvalidClientMetadata, "redirect_uri not found in client metadata"
    end

    def loopback_redirect_components(url)
      uri = URI(url)

      unless uri.is_a?(URI::HTTP) && uri.scheme == 'http' && ['127.0.0.1', '[::1]'].include?(uri.host) &&
          !uri.userinfo && !uri.fragment && uri.port.between?(1, 65_535)
        return nil
      end

      # compare the localhost URLs while ignoring the port
      # "redirect_uri (string, multiple query parameters allowed, optional):
      #  allows declaring a local redirect/callback URL, with path component matched but port numbers ignored"

      URI.split(url).tap { |components| components[3] = nil }
    rescue URI::InvalidURIError
      nil
    end

    def initialize_client_assertion(key)
      if @client_metadata.confidential?
        raise InvalidClientMetadata, "Confidential clients require a signing_key" if key.nil?
      else
        raise InvalidClientMetadata, "Public clients must not supply a signing_key" unless key.nil?
        return nil
      end

      assertion = PAR::ClientAssertion.new(client_id: @client_id, signing_key: key)
      private_key = assertion.signing_key

      if @client_metadata.jwks
        public_key = private_key.to_public_map.to_h

        key_in_jwks = @client_metadata.jwks['keys'].any? { |candidate|
          metadata_key_matches_public_key?(candidate, public_key)
        }

        raise InvalidClientMetadata, "signing_key must match an active public key advertised in jwks" if !key_in_jwks
      end

      @client_assertion = assertion
      @signing_key_kid = private_key.fields.fetch('kid')
      @signing_key_thumbprint = private_key.thumbprint('SHA256')
    end

    def metadata_key_matches_public_key?(candidate, public_key)
      return false if candidate['revoked']
      return false if candidate.key?('alg') && candidate['alg'] != PAR::ClientAssertion::ALGORITHM
      return false if candidate.key?('use') && candidate['use'] != 'sig'
      return false if candidate.key?('key_ops') && !candidate['key_ops'].include?('verify')

      %w[kid kty crv x y].all? { |field| candidate[field] == public_key[field] }
    end


    # --- used in authorize ---

    def validate_auth_params(handle, pds, scope)
      unless scope.is_a?(String) && scope.valid_encoding? && Metadata::ClientMetadata::SCOPE_PATTERN.match?(scope)
        raise ArgumentError, "scope must contain valid tokens separated by single spaces"
      end

      requested_scopes = scope.split(' ')
      raise ArgumentError, "scope must include 'atproto'" unless requested_scopes.include?('atproto')

      undeclared = requested_scopes - @client_metadata.scope.split(' ')

      unless undeclared.empty?
        raise ArgumentError, "scope contains values not declared in client metadata: #{undeclared.join(' ')}"
      end

      raise ArgumentError, "handle or pds must be provided" if handle.nil? && pds.nil?
      raise ArgumentError, "cannot provide both handle and pds" if handle && pds
      raise ArgumentError, "pds must be a full URL" if pds && URI(pds).class == URI::Generic
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
        req.scope = session.requested_scope
        req.login_hint = login_hint if login_hint
        req.code_challenge = session.pkce_challenge

        if @client_metadata.confidential?
          req.client_assertion = @client_assertion
        end
      end

      par_response = par_client.submit(par_request, session: session)

      par_client.build_authorization_url(
        request_uri: par_response.request_uri,
        client_id: @client_id
      )
    end


    # --- used in handle_callback ---

    def validate_callback_params(callback_params)
      raise CallbackError, "Callback parameters must be a hash" unless callback_params.is_a?(Hash)

      params = callback_params.transform_keys(&:to_s)

      if params.key?('error')
        unless params['error'].is_a?(String) && !params['error'].empty?
          raise CallbackError, "Callback error must be a nonempty string"
        end

        %w[error_description error_uri].each do |field|
          unless params[field].nil? || params[field].is_a?(String)
            raise CallbackError, "Callback #{field} must be a string"
          end
        end

        message = [params['error'], params['error_description']].compact.join(": ")

        raise CallbackError.new(
          "Authorization failed: #{message}",
          error_code: params['error'],
          error_description: params['error_description'],
          error_uri: params['error_uri']
        )
      end

      %w[code state iss].each do |field|
        unless params[field].is_a?(String) && !params[field].empty?
          raise CallbackError, "Callback #{field} must be a nonempty string"
        end
      end

      params
    end

    def exchange_code(code:, session:)
      response = dpop_client.with_nonce_handling(session.session_id, session.auth_server.token_endpoint) do
        make_token_request(code, session)
      end

      raise TokenError, "Token request failed: #{response[:status]}" unless response_status(response) == 200

      tokens = Token::Response.parse(response)
      validate_token_identity(tokens, session)

      tokens
    rescue Token::Response::Error => e
      raise TokenError, e.message
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
        body.merge!(
          client_assertion_type: PAR::CLIENT_ASSERTION_TYPE,
          client_assertion: @client_assertion.generate_jwt(audience: session.auth_server.issuer)
        )
      end

      http.post(
        session.auth_server.token_endpoint,
        body: body,
        headers: {
          "Content-Type" => "application/x-www-form-urlencoded",
          "DPoP" => dpop_proof
        }
      )
    end

    def validate_token_identity(tokens, session)
      if session.did
        raise Token::IdentityMismatchError, "Subject mismatch in token response" if session.did != tokens.sub
      else
        validate_subject_pds(tokens.sub, session)
      end
    rescue Token::IdentityMismatchError => e
      revoke_rejected_refresh_token(tokens.refresh_token, session) if tokens.refresh_token
      raise TokenError, e.message
    rescue Token::IdentityLookupError => e
      raise TokenError, "#{e.message}; start authorization again"
    rescue Token::IdentityError => e
      raise TokenError, e.message
    end

    def revoke_rejected_refresh_token(token, session)
      return unless session.can_be_revoked?

      revocation = Token::Revocation.new(
        session: session,
        dpop_client: @dpop_client,
        client_metadata: @client_metadata,
        client_assertion: @client_assertion
      )

      revocation.revoke_token(token, token_type: 'refresh_token')
    rescue StandardError
      # Cleanup failures must not replace the original identity error.
      nil
    end
  end
end
