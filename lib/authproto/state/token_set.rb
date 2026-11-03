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
      # @param token_type [String] must be `DPoP` (case-insensitive)
      # @param expires_in [Integer] lifetime of the access token in seconds; negative value means it's already expired
      # @param scope [String] nonempty space-separated granted scopes
      # @param sub [String] nonempty account DID
      # @param refresh_token [String, nil] nonempty refresh token, if issued
      # @raise [ArgumentError] if token fields have invalid types or values
      #
      def initialize(access_token:, token_type:, expires_in:, scope:, sub:, refresh_token: nil)
        validate_token_type(token_type)

        validate_required('access_token', access_token)
        validate_required('scope', scope)
        validate_required('sub', sub)
        validate_required('refresh_token', refresh_token) unless refresh_token.nil?

        validate_expires_in(expires_in)

        @access_token = access_token
        @refresh_token = refresh_token
        @scope = scope
        @sub = sub
        @expires_at = Time.now + expires_in
      end

      # Returns the token scheme, which is always `DPoP`.
      #
      # @return [String] `DPoP`
      #
      def token_type
        'DPoP'
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
        unless type.is_a?(String) && type.casecmp?('DPoP')
          raise ArgumentError, "token_type must be DPoP"
        end
      end

      def validate_required(name, value)
        unless value.is_a?(String) && !value.empty?
          raise ArgumentError, "#{name} must be a nonempty string"
        end
      end

      def validate_expires_in(expires_in)
        return if expires_in.is_a?(Integer)

        raise ArgumentError, "expires_in must be an integer"
      end
    end
  end
end
