# frozen_string_literal: true

module AuthProto
  module DPoP

    #
    # @api private
    #
    # Represents a stored nonce with its server origin.
    #

    class StoredNonce

      # Nonce value received from the server.
      # @return [String]
      attr_reader :value

      # Server origin associated with the nonce.
      # @return [String]
      attr_reader :origin

      # Creation timestamp; defaults to integer Unix seconds.
      # @return [Integer, Time]
      attr_reader :timestamp

      # Creates a nonce record without validation.
      #
      # @param value [String] server-provided nonce
      # @param origin [String] server origin URL
      # @param timestamp [Integer, Time, nil] timestamp to retain, or `nil` for current Unix seconds
      #
      def initialize(value, origin, timestamp: nil)
        @value = value
        @origin = origin
        @timestamp = timestamp || Time.now.to_i
      end
    end
  end
end
