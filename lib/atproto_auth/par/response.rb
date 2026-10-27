# frozen_string_literal: true

module AuthProto
  module PAR

    #
    # Represents a PAR response
    #

    class Response

      # Opaque PAR request URI used in the browser authorization URL.
      # @return [String]
      attr_reader :request_uri

      # Lifetime of the request URI in seconds.
      # @return [Integer]
      attr_reader :expires_in

      # Creates and validates a PAR response.
      #
      # @param request_uri [String] nonempty request URI issued by the authorization server
      # @param expires_in [Integer, String] positive lifetime in seconds; converted with `to_i`
      # @raise [Error] if the URI is empty or expiry is not positive
      #
      def initialize(request_uri:, expires_in:)
        @request_uri = request_uri
        @expires_in = expires_in.to_i
        validate_response
      end


      private

      def validate_response
        raise Error, "request_uri is required" if request_uri.nil? || request_uri.empty?
        raise Error, "expires_in must be positive" unless expires_in.positive?
      end
    end
  end
end
