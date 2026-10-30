# frozen_string_literal: true

module AuthProto
  module State

    #
    # Represents a set of OAuth tokens and their associated metadata
    #

    class TokenSet

      # DPoP-bound access token.
      # @return [String]
      attr_reader :access_token

      # Refresh token, if issued.
      # @return [String, nil]
      attr_reader :refresh_token

      # Token scheme; always `DPoP`.
      # @return [String]
      attr_reader :token_type

      # Space-separated granted scopes.
      # @return [String]
      attr_reader :scope

      # Access token expiry time.
      # @return [Time]
      attr_reader :expires_at

      # DID of the authenticated account.
      # @return [String]
      attr_reader :sub

      # Creates a token set and calculates its expiry from the current time.
      #
      # @param access_token [String] nonempty DPoP-bound access token
      # @param token_type [String] must be `DPoP`
      # @param expires_in [Integer] lifetime in seconds; negative values represent expired tokens
      # @param scope [String] nonempty space-separated granted scopes
      # @param sub [String] nonempty account DID
      # @param refresh_token [String, nil] refresh token, if issued
      # @raise [ArgumentError] if required strings are missing, the token type is wrong, or expiry is not an integer
      #
      def initialize(
        access_token:,
        token_type:,
        expires_in:,
        scope:,
        sub:,
        refresh_token: nil
      )
        validate_token_type(token_type)
        validate_required('access_token', access_token)
        validate_required('scope', scope)
        validate_required('sub', sub)
        validate_expires_in(expires_in)

        @access_token = access_token
        @refresh_token = refresh_token
        @token_type = token_type
        @scope = scope
        @sub = sub
        @expires_at = Time.now + expires_in
      end

      # Whether this token set includes a refresh token
      # @return [Boolean]
      def renewable?
        !@refresh_token.nil? && !@refresh_token.empty?
      end

      # Checks expiry, treating tokens close to expiry as already expired.
      #
      # @param buffer [Numeric] seconds before actual expiry to consider the token expired
      # @return [Boolean] whether the token has expired or is within the buffer
      #
      def expired?(buffer = 30)
        Time.now >= (@expires_at - buffer)
      end


      private

      def validate_token_type(type)
        raise ArgumentError, "token_type must be DPoP" unless type == 'DPoP'
      end

      def validate_required(name, value)
        raise ArgumentError, "#{name} is required" if value.nil? || value.empty?
      end

      def validate_expires_in(expires_in)
        return if expires_in.is_a?(Integer)

        raise ArgumentError, "expires_in must be an integer"
      end
    end
  end
end
