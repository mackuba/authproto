# frozen_string_literal: true

begin
  require 'redis'
rescue LoadError
  warn "Error: missing Redis adapter. Add this to your Gemfile:"
  warn "  gem 'redis', '~> 5.4'"
  raise
end

module AuthProto
  module Storage

    #
    # Redis storage implementation
    #

    class Redis < Interface

      # Error raised for Redis-specific issues
      class RedisError < StorageError; end

      # Creates a Redis adapter; connections are opened lazily by the Redis client.
      #
      # Requires the optional `redis` gem. Values are stored using Redis string semantics.
      #
      # @param redis_client [::Redis, nil] existing Redis connection, or `nil` for `Redis.new`
      #
      def initialize(redis_client: nil)
        super()
        @redis_client = redis_client || ::Redis.new
      end

      # Stores a value in Redis storage.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @param value [#to_s, nil] value converted to Redis string data; `nil` is stored as an empty string
      # @param ttl [Integer, nil] positive expiry in seconds, or `nil` for no new expiry
      #
      # @return [true] if the write succeeds
      # @raise [StorageError] if key or TTL validation fails
      # @raise [RedisError] if the backend operation fails
      #
      def set(key, value, ttl: nil)
        validate_key(key)
        validate_ttl(ttl)

        @redis_client.set(key, value, ex: ttl)
        true
      rescue ::Redis::BaseError => e
        raise RedisError, "Failed to set value: #{e.message}"
      end

      # Retrieves an unexpired value from Redis storage.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @return [String, nil] stored value, or `nil` if missing/expired; empty Redis strings also return `nil`
      # @raise [StorageError] if the key is invalid
      # @raise [RedisError] if the backend operation fails
      #
      def get(key)
        validate_key(key)

        value = @redis_client.get(key)
        value.nil? || value == "" ? nil : value
      rescue ::Redis::BaseError => e
        raise RedisError, "Failed to get value: #{e.message}"
      end

      # Deletes a key from Redis storage.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @return [Boolean] whether a stored row/key was deleted
      # @raise [StorageError] if the key is invalid
      # @raise [RedisError] if the backend operation fails
      #
      def delete(key)
        validate_key(key)

        @redis_client.del(key).positive?
      rescue ::Redis::BaseError => e
        raise RedisError, "Failed to delete value: #{e.message}"
      end

      # Checks for an unexpired key in Redis storage.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @return [Boolean] whether the key exists and has not expired
      # @raise [StorageError] if the key is invalid
      # @raise [RedisError] if the backend operation fails
      #
      def exists?(key)
        validate_key(key)

        @redis_client.exists?(key)
      rescue ::Redis::BaseError => e
        raise RedisError, "Failed to check existence: #{e.message}"
      end

      # Acquires a Redis lock, yields, and releases the lock when the block exits.
      #
      # Locks expire after `ttl` seconds and are not renewed while the block runs.
      # Exceptions from the block propagate to the caller.
      #
      # @param key [String] nonempty lock key beginning with `atproto:`
      # @param ttl [Integer] positive lock lifetime in seconds
      #
      # @yield work to protect with the lock
      # @yieldreturn [Object] value returned to the caller
      # @return [Object] block result
      #
      # @raise [LockError] if another owner holds the lock
      # @raise [StorageError] if key or TTL validation fails
      # @raise [ArgumentError] if no block is supplied
      # @raise [RedisError] if the backend operation fails
      #
      def with_lock(key, ttl: 30)
        raise ArgumentError, "Block required" unless block_given?

        acquired = acquire_lock(key, ttl: ttl)
        raise LockError, "Failed to acquire lock" unless acquired

        begin
          yield
        ensure
          release_lock(key)
        end
      rescue ::Redis::BaseError => e
        raise RedisError, "Lock operation failed: #{e.message}"
      end

      private

      def acquire_lock(key, ttl:)
        validate_key(key)
        validate_ttl(ttl)

        lock_key = "atproto:locks:#{key}"
        @redis_client.set(lock_key, Time.now.to_i, nx: true, ex: ttl)
      rescue ::Redis::BaseError => e
        raise RedisError, "Failed to acquire lock: #{e.message}"
      end

      def release_lock(key)
        validate_key(key)

        lock_key = "atproto:locks:#{key}"
        @redis_client.del(lock_key).positive?
      rescue ::Redis::BaseError => e
        raise RedisError, "Failed to release lock: #{e.message}"
      end
    end
  end
end
