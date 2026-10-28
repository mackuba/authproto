# frozen_string_literal: true

require 'monitor'

module AuthProto
  module Storage

    #
    # Thread-safe in-memory storage implementation
    #

    class Memory < Interface

      # Creates an empty in-memory store and starts a background expiry-cleanup thread.
      #
      # Data and locks are local to this instance and are lost on process exit.
      #
      def initialize
        super
        @data = {}
        @locks = {}
        @expirations = {}
        @monitor = Monitor.new
        @cleanup_interval = 60 # 1 minute
        start_cleanup_thread
      end

      # Stores a value in Memory storage.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @param value [Object] value retained by reference
      # @param ttl [Integer, nil] positive expiry in seconds, or `nil` for no new expiry
      # @return [true] if the write succeeds
      # @raise [StorageError] if key or TTL validation fails
      #
      def set(key, value, ttl: nil)
        validate_key(key)
        validate_ttl(ttl)

        @monitor.synchronize do
          @data[key] = value
          set_expiration(key, ttl) if ttl
          true
        end
      end

      # Retrieves an unexpired value from Memory storage.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @return [Object, nil] stored value, or `nil` if missing/expired
      # @raise [StorageError] if the key is invalid
      #
      def get(key)
        validate_key(key)

        @monitor.synchronize do
          return nil if expired?(key)

          @data[key]
        end
      end

      # Deletes a key from Memory storage.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @return [true] `true`, including when the key was absent
      # @raise [StorageError] if the key is invalid
      #
      def delete(key)
        validate_key(key)

        @monitor.synchronize do
          @data.delete(key)
          @expirations.delete(key)
          true
        end
      end

      # Checks for an unexpired key in Memory storage.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @return [Boolean] whether the key exists and has not expired
      # @raise [StorageError] if the key is invalid
      #
      def exists?(key)
        validate_key(key)

        @monitor.synchronize do
          return false unless @data.key?(key)
          return false if expired?(key)

          true
        end
      end

      # Acquires a Memory lock, yields, and releases the lock when the block exits.
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
      end

      # Clears all values, expiration records and locks from this store.
      # @return [void]
      def clear
        @monitor.synchronize do
          @data.clear
          @expirations.clear
          @locks.clear
        end
      end

      private

      def acquire_lock(key, ttl:)
        validate_key(key)
        validate_ttl(ttl)
        lock_key = "lock:#{key}"

        @monitor.synchronize do
          return false if @locks[lock_key] && !lock_expired?(lock_key)

          @locks[lock_key] = Time.now.to_i + ttl
          true
        end
      end

      def release_lock(key)
        validate_key(key)
        lock_key = "lock:#{key}"

        @monitor.synchronize do
          @locks.delete(lock_key)
          true
        end
      end

      def expired?(key)
        return false unless @expirations.key?(key)

        expiry = @expirations[key]
        if Time.now.to_i >= expiry
          @data.delete(key)
          @expirations.delete(key)
          true
        else
          false
        end
      end

      def lock_expired?(lock_key)
        expiry = @locks[lock_key]
        return false unless expiry

        if Time.now.to_i >= expiry
          @locks.delete(lock_key)
          true
        else
          false
        end
      end

      def set_expiration(key, ttl)
        @expirations[key] = Time.now.to_i + ttl
      end

      def cleanup_expired
        @monitor.synchronize do
          now = Time.now.to_i

          # Cleanup expired data
          @expirations.each do |key, expiry|
            if now >= expiry
              @data.delete(key)
              @expirations.delete(key)
            end
          end

          # Cleanup expired locks
          @locks.delete_if { |key, expiry| now >= expiry }
        end
      end

      def start_cleanup_thread
        Thread.new do
          loop do
            sleep @cleanup_interval
            cleanup_expired
          rescue StandardError => e
            # Log error but keep thread running
            AuthProto.configuration.logger.error "Storage cleanup error: #{e.message}"
          end
        end
      end
    end
  end
end
