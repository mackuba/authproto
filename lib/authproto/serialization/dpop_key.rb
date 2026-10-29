# frozen_string_literal: true

require_relative '../dpop/key_manager'
require_relative 'base'

module AuthProto
  module Serialization

    #
    # Handles serialization of DPoP keys
    #

    class DPoPKey < Base

      # Returns the envelope type used by this serializer.
      # @return [String] `DPoPKey`
      def type_identifier
        "DPoPKey"
      end

      private

      def validate_object(obj)
        return if obj.is_a?(AuthProto::DPoP::KeyManager)

        raise ValidationError, "Expected KeyManager object, got #{obj.class}"
      end

      def serialize_data(obj)
        obj.to_jwk(include_private: true).to_h
      end

      def deserialize_data(data)
        AuthProto::DPoP::KeyManager.from_jwk(data)
      end
    end
  end
end
