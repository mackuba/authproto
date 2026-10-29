# frozen_string_literal: true

require 'fileutils'
require 'securerandom'

require_relative 'interface'

begin
  require 'sqlite3'
rescue LoadError
  warn "Error: missing SQLite adapter. Add this to your Gemfile:"
  warn "  gem 'sqlite3', '~> 2.9'"
  raise
end

module AuthProto
  module Storage

    #
    # SQLite storage implementation
    #

    class SQLite < Interface

      # Error raised for SQLite-specific issues
      class SQLiteError < StorageError; end

      # Default SQLite lock-wait timeout in milliseconds.
      # @return [Integer]
      DEFAULT_BUSY_TIMEOUT = 5_000

      # Opens a SQLite store, creating parent directories and tables as needed.
      #
      # Enables WAL mode and full synchronous writes. Requires the optional `sqlite3` gem.
      #
      # @param path [String] database file path
      # @param busy_timeout [Integer] nonnegative SQLite lock-wait timeout in milliseconds
      # @raise [ArgumentError] if `busy_timeout` is not a nonnegative integer
      # @raise [SQLiteError] if opening or configuring the database fails
      # @raise [SystemCallError] if creating a parent directory fails
      #
      def initialize(path:, busy_timeout: DEFAULT_BUSY_TIMEOUT)
        super()

        unless busy_timeout.is_a?(Integer) && busy_timeout >= 0
          raise ArgumentError, "Busy timeout must be a non-negative integer"
        end

        FileUtils.mkdir_p(File.dirname(path))

        @database = SQLite3::Database.new(path)
        @database.busy_timeout = busy_timeout

        configure_database
        create_schema
      rescue SQLite3::Exception => e
        raise SQLiteError, "Failed to initialize database: #{e.message}"
      end

      # Stores a value in SQLite storage.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @param value [String, Numeric, nil] SQLite-compatible scalar value; strings are used for serialized OAuth data
      # @param ttl [Integer, nil] positive expiry in seconds, or `nil` for no new expiry
      #
      # @return [true] if the write succeeds
      # @raise [StorageError] if key or TTL validation fails
      # @raise [SQLiteError] if the backend operation fails
      #
      def set(key, value, ttl: nil)
        validate_key(key)
        validate_ttl(ttl)

        expires_at = ttl && (current_time + ttl)

        @database.execute(
          <<~SQL,
            INSERT INTO atproto_storage (key, value, expires_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at
          SQL
          [key, value, expires_at]
        )

        true
      rescue SQLite3::Exception => e
        raise SQLiteError, "Failed to set value: #{e.message}"
      end

      # Retrieves an unexpired value from SQLite storage.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @return [String, Numeric, nil] stored value, or `nil` if missing/expired
      # @raise [StorageError] if the key is invalid
      # @raise [SQLiteError] if the backend operation fails
      #
      def get(key)
        validate_key(key)

        now = current_time
        row = @database.get_first_row(
          <<~SQL,
            SELECT value
            FROM atproto_storage
            WHERE key = ? AND (expires_at IS NULL OR expires_at > ?)
          SQL
          [key, now]
        )

        if row
          row.first
        else
          delete_expired_value(key, now)
          nil
        end
      rescue SQLite3::Exception => e
        raise SQLiteError, "Failed to get value: #{e.message}"
      end

      # Deletes a key from SQLite storage.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @return [Boolean] whether a stored row/key was deleted
      # @raise [StorageError] if the key is invalid
      # @raise [SQLiteError] if the backend operation fails
      #
      def delete(key)
        validate_key(key)

        result = @database.get_first_value(
          "DELETE FROM atproto_storage WHERE key = ? RETURNING 1",
          [key]
        )

        !result.nil?
      rescue SQLite3::Exception => e
        raise SQLiteError, "Failed to delete value: #{e.message}"
      end

      # Checks for an unexpired key in SQLite storage.
      #
      # @param key [String] nonempty key beginning with `atproto:`
      # @return [Boolean] whether the key exists and has not expired
      # @raise [StorageError] if the key is invalid
      # @raise [SQLiteError] if the backend operation fails
      #
      def exists?(key)
        validate_key(key)

        now = current_time

        exists = @database.get_first_value(
          <<~SQL,
            SELECT 1
            FROM atproto_storage
            WHERE key = ? AND (expires_at IS NULL OR expires_at > ?)
          SQL
          [key, now]
        )

        if exists
          true
        else
          delete_expired_value(key, now)
          false
        end
      rescue SQLite3::Exception => e
        raise SQLiteError, "Failed to check existence: #{e.message}"
      end

      # Acquires a SQLite lock, yields, and releases the lock when the block exits.
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
      # @raise [SQLiteError] if the backend operation fails
      #
      def with_lock(key, ttl: 30)
        raise ArgumentError, "Block required" unless block_given?

        owner = acquire_lock(key, ttl: ttl)
        raise LockError, "Failed to acquire lock" unless owner

        begin
          yield
        ensure
          release_lock(key, owner)
        end
      end

      # Closes the underlying SQLite connection.
      #
      # @return [void]
      # @raise [SQLiteError] if closing the database fails
      #
      def close
        @database.close
      rescue SQLite3::Exception => e
        raise SQLiteError, "Failed to close database: #{e.message}"
      end

      private

      def configure_database
        @database.execute("PRAGMA journal_mode = WAL")
        @database.execute("PRAGMA synchronous = FULL")
      end

      def create_schema
        @database.execute_batch(<<~SQL)
          CREATE TABLE IF NOT EXISTS atproto_storage (
            key TEXT PRIMARY KEY NOT NULL,
            value,
            expires_at REAL
          );

          CREATE TABLE IF NOT EXISTS atproto_locks (
            key TEXT PRIMARY KEY NOT NULL,
            owner TEXT NOT NULL,
            expires_at REAL NOT NULL
          );
        SQL
      end

      def acquire_lock(key, ttl:)
        validate_key(key)
        validate_ttl(ttl)

        now = current_time
        owner = SecureRandom.uuid

        acquired_owner = @database.get_first_value(
          <<~SQL,
            INSERT INTO atproto_locks (key, owner, expires_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET owner = excluded.owner, expires_at = excluded.expires_at
              WHERE atproto_locks.expires_at <= ?
            RETURNING owner
          SQL
          [key, owner, now + ttl, now]
        )

        acquired_owner ? owner : nil
      rescue SQLite3::Exception => e
        raise SQLiteError, "Failed to acquire lock: #{e.message}"
      end

      def release_lock(key, owner)
        result = @database.get_first_value(
          "DELETE FROM atproto_locks WHERE key = ? AND owner = ? RETURNING 1",
          [key, owner]
        )

        !result.nil?
      rescue SQLite3::Exception => e
        raise SQLiteError, "Failed to release lock: #{e.message}"
      end

      def delete_expired_value(key, now)
        @database.execute(
          "DELETE FROM atproto_storage WHERE key = ? AND expires_at <= ?",
          [key, now]
        )
      end

      def current_time
        Time.now.to_f
      end
    end
  end
end
