# frozen_string_literal: true

module AuthProto
  module State

    #
    # A representation of a session's data that's meant to be used from outside of the AuthProto library.
    #

    class SessionInfo

      # Creates an instance of {SessionInfo} backed by the supplied {Session}.
      #
      # @param session [Session] session whose data this object will expose
      #
      def initialize(session)
        @session = session
      end

      # The session's unique identifier used to load and update it in the configured storage.
      # @return [String]
      #
      def session_id
        @session.session_id
      end

      # Current access token, if authorized.
      # @return [String, nil]
      #
      def access_token
        @session.synchronize { @session.tokens&.access_token }
      end

      # Current refresh token, if issued.
      # @return [String, nil]
      #
      def refresh_token
        @session.synchronize { @session.tokens&.refresh_token }
      end

      # Expiry time of the current access token, if assigned.
      # @return [Time, nil]
      #
      def expires_at
        @session.synchronize { @session.tokens&.expires_at }
      end

      # Remaining access token lifetime in seconds, if an access token is available.
      # @return [Integer, nil]
      #
      def expires_in
        @session.synchronize do
          tokens = @session.tokens
          (tokens.expires_at - Time.now).to_i if tokens
        end
      end

      # Space-separated list of permissions requested during authorization.
      # @return [String]
      #
      def requested_scope
        @session.requested_scope
      end

      # Space-separated list of permissions that have been actually granted.
      # @return [String, nil]
      #
      def granted_scope
        @session.synchronize { @session.tokens&.scope }
      end

      # The DID of the authorized account, if known.
      # @return [String, nil]
      #
      def did
        @session.did
      end

      # The URL of the authorized account's PDS, if known.
      # @return [String, nil]
      #
      def pds
        @session.pds
      end

      # Returns the current session data properties as a Hash.
      #
      # @return [Hash{Symbol => String, Integer, Time, nil}] current session data
      #
      def to_h
        @session.synchronize do
          {
            session_id: session_id,
            access_token: access_token,
            refresh_token: refresh_token,
            expires_in: expires_in,
            expires_at: expires_at,
            requested_scope: requested_scope,
            granted_scope: granted_scope,
            did: did,
            pds: pds
          }
        end
      end

      # True if the authorization is still pending (has not completed the callback and received access tokens).
      # @return [Boolean]
      #
      def pending?
        @session.pending?
      end

      # True if the access token is currently valid, including the expiry buffer.
      # @return [Boolean]
      #
      def tokens_valid?
        @session.tokens_valid?
      end

      # Whether the session is currently authorized.
      # @return [Boolean]
      #
      alias authorized? tokens_valid?

      # True if the session currently has a refresh token.
      # @return [Boolean]
      #
      def renewable?
        @session.renewable?
      end

      # Tells if some of the originally requested permissions are missing from the current grant.
      # @return [Boolean]
      #
      def has_limited_scope?
        @session.synchronize do
          tokens = @session.tokens
          tokens ? !(@session.requested_scope.split - tokens.scope.split).empty? : false
        end
      end

      # True if the authorization server has an advertised public token revocation endpoint.
      # @return [Boolean]
      #
      def can_be_revoked?
        @session.can_be_revoked?
      end
    end
  end
end
