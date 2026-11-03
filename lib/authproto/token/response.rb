# frozen_string_literal: true

require 'json'

require_relative '../errors'
require_relative '../http_helpers'
require_relative '../state/token_set'

module AuthProto
  module Token

    #
    # Parses successful token responses shared by code exchange and refresh.
    #

    class Response
      extend HTTPHelpers

      # Error raised when a successful token response is malformed.
      class Error < AuthProto::Error; end

      # Validates the response representation and constructs its token set.
      # Identity checks remain the responsibility of the calling authorization flow.
      #
      # @param response [Hash] successful HTTP response from the token endpoint
      # @return [State::TokenSet] validated tokens
      # @raise [Error] if the response has an invalid content type, body or token fields
      #
      def self.parse(response)
        content_type = response_header(response, 'Content-Type', strip_parameters: true)

        unless content_type&.casecmp?('application/json')
          raise Error, "Token response Content-Type must be application/json"
        end

        raise Error, "Missing token response body" unless response[:body].is_a?(String)

        data = JSON.parse(response[:body])
        raise Error, "Token response must be a JSON object" unless data.is_a?(Hash)

        ['access_token', 'token_type', 'expires_in', 'scope', 'sub'].each do |field|
          raise Error, "Missing #{field} in token response" if data[field].nil?
        end

        unless data['expires_in'].is_a?(Integer) && data['expires_in'].positive?
          raise Error, "Invalid expires_in in token response: must be a positive integer"
        end

        if data.key?('refresh_token') && data['refresh_token'].nil?
          raise Error, "Invalid refresh_token in token response"
        end

        tokens = State::TokenSet.new(
          access_token: data['access_token'],
          refresh_token: data['refresh_token'],
          token_type: data['token_type'],
          expires_in: data['expires_in'],
          scope: data['scope'],
          sub: data['sub']
        )

        raise Error, "Invalid scope in token response: missing atproto" unless tokens.scope.split.include?('atproto')

        tokens
      rescue JSON::ParserError, ArgumentError => e
        raise Error, "Invalid token response: #{e.message}"
      end
    end
  end
end
