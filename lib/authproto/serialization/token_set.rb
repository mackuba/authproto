# frozen_string_literal: true

require 'time'

require_relative '../state/token_set'
require_relative 'base'

module AuthProto
  module Serialization

    #
    # Handles serialization of TokenSet objects
    #

    class TokenSet < Base

      # Returns the envelope type used by this serializer.
      # @return [String] `TokenSet`
      def type_identifier
        "TokenSet"
      end

      private

      def validate_object(obj)
        return if obj.is_a?(AuthProto::State::TokenSet)

        raise ValidationError, "Expected TokenSet object, got #{obj.class}"
      end

      def serialize_data(obj)
        {
          access_token: obj.access_token,
          refresh_token: obj.refresh_token,
          token_type: obj.token_type,
          expires_at: obj.expires_at.utc.iso8601,
          scope: obj.scope,
          sub: obj.sub
        }
      end

      def deserialize_data(data)
        AuthProto::State::TokenSet.new(
          access_token: data['access_token'],
          refresh_token: data['refresh_token'],
          token_type: data['token_type'],
          expires_in: (Time.parse(data['expires_at']) - Time.now).to_i,
          scope: data['scope'],
          sub: data['sub']
        )
      end
    end
  end
end
