# frozen_string_literal: true

module AuthProto

  #
  # Storage contracts and optional memory, Redis and SQLite adapters for OAuth state.
  #

  module Storage

    # Base error class for storage operations
    class StorageError < AuthProto::Error; end

    # Error for lock-related operations
    class LockError < StorageError; end

    #
    # Base storage interface that all implementations must conform to
    #

    class Interface

      # Stores a value, optionally with an expiry.
      # Implementations must validate keys and TTLs. Accepted value types depend on the backend.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @param value [Object] backend-compatible value to store
      # @param ttl [Integer, nil] positive lifetime in seconds, or `nil` for no expiry
      # @return [Boolean] whether the write succeeded
      # @raise [StorageError] if validation or storage fails
      # @raise [NotImplementedError] unless overridden by a storage adapter
      #
      def set(key, value, ttl: nil)
        raise NotImplementedError
      end

      # Reads an unexpired value.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @return [Object, nil] stored value, or `nil` if missing/expired
      # @raise [StorageError] if validation or storage fails
      # @raise [NotImplementedError] unless overridden by a storage adapter
      #
      def get(key)
        raise NotImplementedError
      end

      # Deletes a stored value.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @return [Boolean] backend deletion status; see adapter-specific semantics
      # @raise [StorageError] if validation or storage fails
      # @raise [NotImplementedError] unless overridden by a storage adapter
      #
      def delete(key)
        raise NotImplementedError
      end

      # Checks whether an unexpired key exists.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @return [Boolean] whether the key exists
      # @raise [StorageError] if validation or storage fails
      # @raise [NotImplementedError] unless overridden by a storage adapter
      #
      def exists?(key)
        raise NotImplementedError
      end

      # Runs a block while holding a lock that expires after the requested TTL.
      #
      # A lock is not renewed automatically; choose a TTL longer than the protected work.
      #
      # @param key [String] nonempty lock key beginning with `atproto:`
      # @param ttl [Integer] positive lock lifetime in seconds
      # @yield block to run after acquiring the lock
      # @yieldreturn [Object] result to return to the caller
      # @return [Object] block result
      # @raise [LockError] if the lock cannot be acquired
      # @raise [StorageError] if validation or backend operations fail
      # @raise [ArgumentError] if no block is supplied
      # @raise [NotImplementedError] unless overridden by a storage adapter
      #
      def with_lock(key, ttl: 30)
        raise NotImplementedError
      end

      protected

      # Validates that a storage key is nonempty and begins with `atproto:`.
      #
      # @param key [String] value to validate
      # @return [void]
      # @raise [StorageError] if the value is invalid
      #
      def validate_key(key)
        raise StorageError, "Key cannot be nil" if key.nil?
        raise StorageError, "Key must be a string" unless key.is_a?(String)
        raise StorageError, "Key cannot be empty" if key.empty?
        raise StorageError, "Invalid key format" unless key.start_with?("atproto:")
      end

      # Validates that a TTL is `nil` or a positive integer.
      #
      # @param ttl [Integer, nil] value to validate
      # @return [void]
      # @raise [StorageError] if the value is invalid
      #
      def validate_ttl(ttl)
        return if ttl.nil?
        raise StorageError, "TTL must be a positive integer" unless ttl.is_a?(Integer) && ttl.positive?
      end
    end
  end
end
