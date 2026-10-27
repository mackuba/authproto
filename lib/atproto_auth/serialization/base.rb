# frozen_string_literal: true

require 'json'
require 'time'

module AuthProto

  #
  # Versioned JSON serialization with encryption of sensitive OAuth fields.
  #

  module Serialization

    # Base class for malformed serialized data and serializer validation errors.
    class Error < AuthProto::Error; end

    # Raised when a serialized envelope uses an invalid or unsupported version.
    class VersionError < Error; end

    # Raised when an envelope type does not match the selected serializer.
    class TypeMismatchError < Error; end

    # Raised when a serializer receives an object of the wrong type.
    class ValidationError < Error; end

    #
    # Base serializer that all type-specific serializers inherit from
    #

    class Base

      # Current JSON envelope schema version.
      # @return [Integer]
      CURRENT_VERSION = 1

      # Field names encrypted recursively before JSON serialization.
      # @return [Array<String>]
      SENSITIVE_FIELDS = [
        "access_token",
        "refresh_token",
        "private_key",
        "d", # EC private key component
        "pkce_verifier"
      ].freeze

      class << self

        # Serializes an object into a versioned JSON envelope, encrypting sensitive fields.
        #
        # Concrete subclasses validate the input type and provide the data representation.
        #
        # @param obj [Object] object supported by the concrete serializer
        # @return [String] JSON with `version`, `type`, timestamps and `data` fields
        # @raise [ValidationError] if the concrete serializer rejects the object
        # @raise [Encryption::EncryptionError] if a sensitive value cannot be encrypted
        # @raise [NotImplementedError] if used without implementing the abstract serializer hooks
        #
        def serialize(obj)
          new.serialize(obj)
        end

        # Restores an object from a versioned JSON envelope, decrypting sensitive fields.
        #
        # The concrete serializer determines the returned object class.
        #
        # @param data [String] JSON previously produced by the matching serializer
        # @return [Object] reconstructed object
        # @raise [Error] if JSON or the envelope format is invalid
        # @raise [TypeMismatchError] if the envelope has a different type identifier
        # @raise [VersionError] if the format version is invalid or unsupported
        # @raise [Encryption::DecryptionError] if sensitive data cannot be authenticated/decrypted
        # @raise [ArgumentError] if reconstructed fields fail validation or date/time parsing
        # @raise [NotImplementedError] if used without implementing the abstract serializer hooks
        #
        def deserialize(data)
          new.deserialize(data)
        end
      end

      # Creates a serializer with a context-aware encryption service.
      # @raise [ArgumentError] if `ATPROTO_MASTER_KEY` is not valid Base64
      #
      def initialize
        @encryption = Encryption::Service.new
      end

      # Serializes an object into a versioned JSON envelope, encrypting sensitive fields.
      #
      # Concrete subclasses validate the input type and provide the data representation.
      #
      # @param obj [Object] object supported by the concrete serializer
      # @return [String] JSON with `version`, `type`, timestamps and `data` fields
      # @raise [ValidationError] if the concrete serializer rejects the object
      # @raise [Encryption::EncryptionError] if a sensitive value cannot be encrypted
      # @raise [NotImplementedError] if used without implementing the abstract serializer hooks
      #
      def serialize(obj)
        validate_object(obj)

        # First serialize the object
        data = {
          version: CURRENT_VERSION,
          type: type_identifier,
          created_at: Time.now.utc.iso8601,
          updated_at: Time.now.utc.iso8601,
          data: serialize_data(obj)
        }

        # Then encrypt sensitive fields
        encrypt_sensitive_fields(data)

        # Finally convert to JSON
        JSON.generate(data)
      end

      # Restores an object from a versioned JSON envelope, decrypting sensitive fields.
      #
      # The concrete serializer determines the returned object class.
      #
      # @param data [String] JSON previously produced by the matching serializer
      # @return [Object] reconstructed object
      # @raise [Error] if JSON or the envelope format is invalid
      # @raise [TypeMismatchError] if the envelope has a different type identifier
      # @raise [VersionError] if the format version is invalid or unsupported
      # @raise [Encryption::DecryptionError] if sensitive data cannot be authenticated/decrypted
      # @raise [ArgumentError] if reconstructed fields fail validation or date/time parsing
      # @raise [NotImplementedError] if used without implementing the abstract serializer hooks
      #
      def deserialize(data)
        parsed = parse_json(data)
        validate_serialized_data(parsed)

        # Decrypt sensitive fields
        decrypt_sensitive_fields(parsed)

        # Deserialize according to version
        deserialize_version(parsed)
      end

      private

      def encrypt_sensitive_fields(data, path: [])
        return unless data.is_a?(Hash)

        data.each do |key, value|
          current_path = path + [key]

          if sensitive_field?(key)
            data[key] = @encryption.encrypt(
              value.to_s,
              context: current_path.join(".")
            )
          elsif value.is_a?(Hash)
            encrypt_sensitive_fields(value, path: current_path)
          elsif value.is_a?(Array)
            value.each_with_index do |v, i|
              encrypt_sensitive_fields(v, path: current_path + [i.to_s]) if v.is_a?(Hash)
            end
          end
        end
      end

      def decrypt_sensitive_fields(data, path: [])
        return unless data.is_a?(Hash)

        data.each do |key, value|
          current_path = path + [key]
          if sensitive_field?(key)
            data[key] = @encryption.decrypt(
              value.transform_keys(&:to_sym),
              context: current_path.join(".")
            )
          elsif value.is_a?(Hash)
            decrypt_sensitive_fields(value, path: current_path)
          elsif value.is_a?(Array)
            value.each_with_index do |v, i|
              decrypt_sensitive_fields(v, path: current_path + [i.to_s]) if v.is_a?(Hash)
            end
          end
        end
      end

      def sensitive_field?(field)
        SENSITIVE_FIELDS.any? do |sensitive_field|
          field.to_s == sensitive_field
        end
      end

      # Type identifier for serialized data
      # @return [String]
      def type_identifier
        raise NotImplementedError
      end

      # Serialize object to hash
      #
      # @param obj [Object] Object to serialize
      # @return [Hash] Serialized data
      #
      def serialize_data(obj)
        raise NotImplementedError
      end

      # Deserialize object from hash
      #
      # @param data [Hash] Serialized data
      # @return [Object] Deserialized object
      #
      def deserialize_data(data)
        raise NotImplementedError
      end

      # Validate object before serialization
      #
      # @param obj [Object] Object to validate
      # @raise [ValidationError] if object is invalid
      #
      def validate_object(obj)
        raise NotImplementedError
      end

      def parse_json(data)
        JSON.parse(data)
      rescue JSON::ParserError => e
        raise Error, "Invalid JSON data: #{e.message}"
      end

      def validate_serialized_data(data)
        raise Error, "Invalid serialized data format" unless data.is_a?(Hash)

        unless data["type"] == type_identifier
          raise TypeMismatchError,
                "Expected type #{type_identifier}, got #{data["type"]}"
        end

        raise VersionError, "Invalid version format" unless data["version"].is_a?(Integer)

        return unless data["version"] > CURRENT_VERSION

        raise VersionError,
              "Version #{data["version"]} not supported"
      end

      def deserialize_version(data)
        case data["version"]
        when 1
          deserialize_data(data["data"])
        else
          raise VersionError,
                "Unknown version: #{data["version"]}"
        end
      end
    end
  end
end
