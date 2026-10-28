# frozen_string_literal: true

require 'monitor'
require 'securerandom'

module AuthProto
  module State

    #
    # Tracks state for an OAuth authorization flow session
    #

    class Session
      include MonitorMixin

      # Unique identifier used to retrieve this session.
      # @return [String]
      attr_reader :session_id

      # Random OAuth state token for callback validation.
      # @return [String]
      attr_reader :state_token

      # OAuth client identifier.
      # @return [String]
      attr_reader :client_id

      # Space-separated requested scopes.
      # @return [String]
      attr_reader :scope

      # Secret PKCE verifier used for code exchange.
      # @return [String]
      attr_reader :pkce_verifier

      # S256 PKCE challenge sent in PAR.
      # @return [String]
      attr_reader :pkce_challenge

      # Bound authorization server, once discovered.
      # @return [ServerMetadata::AuthorizationServer, nil]
      attr_reader :auth_server

      # Bound account DID, once resolved.
      # @return [String, nil]
      attr_reader :did

      # Most recently assigned tokens, if any.
      # @return [TokenSet, nil]
      attr_reader :tokens

      # Creates session identifiers, a state token, and a PKCE verifier/challenge pair.
      #
      # @param client_id [String] OAuth client ID
      # @param scope [String] requested space-separated scopes
      # @param auth_server [ServerMetadata::AuthorizationServer, nil] pre-resolved authorization server
      # @param did [String, nil] pre-resolved account DID
      # @raise [PKCE::Error] if PKCE generation fails
      #
      def initialize(client_id:, scope:, auth_server: nil, did: nil)
        super() # Initialize MonitorMixin

        @session_id = SecureRandom.uuid
        @state_token = SecureRandom.urlsafe_base64(32)
        @client_id = client_id
        @scope = scope
        @auth_server = auth_server
        @did = did

        # Generate PKCE values
        @pkce_verifier = PKCE.generate_verifier
        @pkce_challenge = PKCE.generate_challenge(@pkce_verifier)

        @tokens = nil
      end

      # Binds this session to an authorization server.
      #
      # @param server [ServerMetadata::AuthorizationServer] resolved authorization server
      # @return [ServerMetadata::AuthorizationServer] assigned server when called as a method
      # @raise [SessionError] if already bound to a server with a different issuer
      #
      def authorization_server=(server)
        synchronize do
          if @auth_server && @auth_server.issuer != server.issuer
            raise SessionError, "Session already bound to different authorization server"
          end

          @auth_server = server
        end
      end

      # Binds this session to an account DID.
      #
      # @param did [String] resolved DID
      # @return [String] assigned DID
      # @raise [SessionError] if already bound to a different DID
      #
      def did=(did)
        synchronize do
          raise SessionError, "Session already bound to different DID" if @did && @did != did

          @did = did
        end
      end

      # Stores tokens in this session object and binds an unbound session to their subject.
      #
      # Call {SessionManager#update_session} to persist the changed session.
      #
      # @param tokens [TokenSet] replacement token set
      # @return [String] existing or newly bound session DID when called as a method
      # @raise [SessionError] if token subject conflicts with the existing session DID
      #
      def tokens=(tokens)
        synchronize do
          raise SessionError, "Token subject doesn't match session DID" if @did && tokens.sub != @did

          @tokens = tokens
          @did ||= tokens.sub
        end
      end

      # Whether this session has valid access tokens
      # @return [Boolean]
      def authorized?
        synchronize do
          !@tokens.nil? && !@tokens.expired?
        end
      end

      # Whether this session can refresh its tokens
      # @return [Boolean]
      def renewable?
        synchronize do
          !@tokens.nil? && @tokens.renewable?
        end
      end

      # Compares a supplied state token with the session token in constant time.
      #
      # @param state [String, nil] callback state token
      # @return [Boolean] whether it matches; `false` for `nil` or a different length
      #
      def validate_state(state)
        return false unless state

        # Use secure comparison to prevent timing attacks
        secure_compare(@state_token, state)
      end

      private

      def secure_compare(str1, str2)
        return false unless str1.bytesize == str2.bytesize

        left = str1.unpack("C*")
        right = str2.unpack("C*")
        result = 0
        left.zip(right) { |x, y| result |= x ^ y }
        result.zero?
      end
    end
  end
end
