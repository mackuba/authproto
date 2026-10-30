# frozen_string_literal: true

require_relative '../par'

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
      # @param expires_in [Integer] positive lifetime in seconds
      # @raise [Error] if the URI is not a nonempty string or expiry is not a positive integer
      #
      def initialize(request_uri:, expires_in:)
        @request_uri = request_uri
        @expires_in = expires_in

        unless @request_uri.is_a?(String) && !@request_uri.empty?
          raise Error, "request_uri must be a nonempty string"
        end

        unless @expires_in.is_a?(Integer) && @expires_in.positive?
          raise Error, "expires_in must be a positive integer"
        end
      end
    end
  end
end
