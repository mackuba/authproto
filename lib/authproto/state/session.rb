# frozen_string_literal: true

require 'monitor'
require 'securerandom'

require_relative '../dpop/key_set'
require_relative '../pkce'
require_relative '../state'

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

      # Random OAuth state token for callback validation, cleared after authorization completes.
      # @return [String, nil]
      attr_reader :state_token

      # Deadline for completing pending authorization, cleared after authorization completes.
      # @return [Time, nil]
      attr_reader :authorization_expires_at

      # OAuth client identifier.
      # @return [String]
      attr_reader :client_id

      # Client-authentication key ID, or nil for public clients.
      # @return [String, nil]
      attr_reader :signing_key_id

      # RFC 7638 SHA-256 thumbprint of the client-authentication public key.
      # @return [String, nil]
      attr_reader :signing_key_thumbprint

      # Private DPoP key belonging to this authorization session.
      # @return [DPoP::KeySet]
      attr_reader :dpop_key

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
      # @return [Metadata::AuthorizationServer, nil]
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
      # @param auth_server [Metadata::AuthorizationServer, nil] pre-resolved authorization server
      # @param did [String, nil] pre-resolved account DID
      # @param signing_key_id [String, nil] client-authentication key ID selected before PAR
      # @param signing_key_thumbprint [String, nil] RFC 7638 SHA-256 thumbprint of that key
      # @param dpop_key [DPoP::KeySet] session key; a fresh key is generated for new sessions by default
      # @param authorization_expires_at [Time, nil] deadline for completing pending authorization
      # @raise [ArgumentError] if the signing key ID or DPoP key has an invalid type
      # @raise [DPoP::KeySet::KeyError] if DPoP key generation fails
      # @raise [PKCE::Error] if PKCE generation fails
      #
      def initialize(client_id:, scope:, auth_server: nil, did: nil, signing_key_id: nil, signing_key_thumbprint: nil,
                     dpop_key: DPoP::KeySet.new, authorization_expires_at: nil)
        super() # Initialize MonitorMixin

        unless signing_key_id.nil? || (signing_key_id.is_a?(String) && !signing_key_id.empty?)
          raise ArgumentError, "signing_key_id must be a nonempty string or nil"
        end

        unless signing_key_thumbprint.nil? || (signing_key_thumbprint.is_a?(String) && !signing_key_thumbprint.empty?)
          raise ArgumentError, "signing_key_thumbprint must be a nonempty string or nil"
        end

        raise ArgumentError, "dpop_key must be a DPoP::KeySet" unless dpop_key.is_a?(DPoP::KeySet)

        @dpop_key = dpop_key
        @client_id = client_id
        @signing_key_id = signing_key_id&.dup&.freeze
        @signing_key_thumbprint = signing_key_thumbprint&.dup&.freeze
        @scope = scope
        @auth_server = auth_server
        @did = did
        @authorization_expires_at = authorization_expires_at

        @session_id = SecureRandom.uuid
        @state_token = SecureRandom.urlsafe_base64(32)

        pkce = PKCE.new
        @pkce_verifier = pkce.verifier
        @pkce_challenge = pkce.challenge

        @tokens = nil
      end

      # Clears the OAuth state token and pending authorization deadline after successful authorization.
      #
      # @return [nil]
      #
      def clear_state_token
        synchronize do
          @state_token = nil
          @authorization_expires_at = nil
        end
      end

      # Binds this session to an authorization server.
      #
      # @param server [Metadata::AuthorizationServer] resolved authorization server
      # @return [Metadata::AuthorizationServer] assigned server when called as a method
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

      # Returns the current tokens and session identifiers, with expiry in seconds from now.
      #
      # @return [Hash{Symbol => String, Integer, nil}, nil] session data, or `nil` before tokens are assigned
      #
      def session_data
        synchronize do
          return nil unless @tokens

          {
            access_token: @tokens.access_token,
            token_type: @tokens.token_type,
            expires_in: (@tokens.expires_at - Time.now).to_i,
            refresh_token: @tokens.refresh_token,
            scope: @tokens.scope,
            session_id: @session_id,
            did: @did
          }
        end
      end

      # Returns true if this session has not completed authorization yet and doesn't contain tokens.
      # @return [Boolean]
      def pending?
        synchronize do
          @tokens.nil?
        end
      end

      # Whether this session has valid access tokens
      # @return [Boolean]
      def tokens_valid?
        synchronize do
          !@tokens.nil? && !@tokens.expired?
        end
      end

      alias authorized? tokens_valid?

      # Whether this session can refresh its tokens
      # @return [Boolean]
      def renewable?
        synchronize do
          !@tokens.nil? && @tokens.renewable?
        end
      end
    end
  end
end
