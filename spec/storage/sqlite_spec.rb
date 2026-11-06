# frozen_string_literal: true

require 'fileutils'
require 'tmpdir'

require_relative 'storage_examples'

describe AuthProto::Storage::SQLite do
  let(:temporary_directory) { Dir.mktmpdir("atproto-auth-sqlite-test") }
  let(:database_path) { File.join(temporary_directory, "storage.sqlite3") }
  let(:storage) { AuthProto::Storage::SQLite.new(path: database_path) }

  # Include shared storage implementation tests
  include_examples "a storage implementation"

  before do
    storage
  end

  after do
    storage.close
    FileUtils.remove_entry(temporary_directory)
  end

  describe "#cleanup_expired_records" do
    it "should delete expired values and locks while preserving live and permanent records" do
      now = Time.utc(2026, 1, 1)
      Time.stubs(:now).returns(now)
      storage.set('atproto:expired', 'expired', ttl: 1)
      storage.set('atproto:live', 'live', ttl: 60)
      storage.set('atproto:permanent', 'permanent')
      storage.send(:acquire_lock, 'atproto:expired-lock', ttl: 1)
      storage.send(:acquire_lock, 'atproto:live-lock', ttl: 60)
      database = SQLite3::Database.new(database_path)

      Time.stubs(:now).returns(now + 1)
      storage.cleanup_expired_records
      storage.cleanup_expired_records

      database.execute("SELECT key FROM atproto_storage ORDER BY key").flatten.should == [
        'atproto:live', 'atproto:permanent'
      ]
      database.execute("SELECT key FROM atproto_locks").flatten.should == ['atproto:live-lock']
      storage.get('atproto:live').should == 'live'
      storage.get('atproto:permanent').should == 'permanent'

      expect {
        storage.with_lock('atproto:live-lock') { true }
      }.to raise_error(AuthProto::Storage::LockError)
    ensure
      database&.close
    end

    it "should wrap database cleanup errors" do
      database = storage.instance_variable_get(:@database)
      database.expects(:execute).raises(SQLite3::Exception, "Database failure")

      expect {
        storage.cleanup_expired_records
      }.to raise_error(AuthProto::Storage::SQLite::SQLiteError, /Failed to clean up expired records/)
    end
  end

  describe "#initialize" do
    it "should create the storage and lock tables" do
      database = SQLite3::Database.new(database_path)
      tables = database.execute(
        <<~SQL
          SELECT name
          FROM sqlite_master
          WHERE type = 'table'
        SQL
      ).flatten

      tables.should include("atproto_storage")
      tables.should include("atproto_locks")
    ensure
      database&.close
    end

    it "should enable WAL journal mode" do
      database = SQLite3::Database.new(database_path)

      database.get_first_value("PRAGMA journal_mode").should == "wal"
    ensure
      database&.close
    end

    it "should configure the busy timeout" do
      custom_storage = AuthProto::Storage::SQLite.new(
        path: File.join(temporary_directory, "custom.sqlite3"),
        busy_timeout: 1_234
      )
      database = custom_storage.instance_variable_get(:@database)

      database.get_first_value("PRAGMA busy_timeout").should == 1_234
    ensure
      custom_storage&.close
    end

    it "should reject invalid busy timeouts" do
      expect {
        AuthProto::Storage::SQLite.new(path: File.join(temporary_directory, "invalid.sqlite3"), busy_timeout: -1)
      }.to raise_error(ArgumentError)

      expect {
        AuthProto::Storage::SQLite.new(
          path: File.join(temporary_directory, "invalid.sqlite3"),
          busy_timeout: "lizard"
        )
      }.to raise_error(ArgumentError)
    end

    it "should create missing parent directories" do
      database_path = File.join(
        temporary_directory,
        "missing",
        "nested",
        "storage.sqlite3"
      )

      nested_storage = AuthProto::Storage::SQLite.new(path: database_path)
      File.exist?(database_path).should be true
    ensure
      nested_storage&.close
    end
  end

  describe "error handling" do
    it "should wrap database initialization errors" do
      expect {
        AuthProto::Storage::SQLite.new(path: temporary_directory)
      }.to raise_error(AuthProto::Storage::SQLite::SQLiteError)
    end
  end

  describe "persistence" do
    it "should share values between connections" do
      storage.set("atproto:test:persistent", "value")
      second_storage = AuthProto::Storage::SQLite.new(path: database_path)

      second_storage.get("atproto:test:persistent").should == "value"
    ensure
      second_storage&.close
    end
  end

  describe "TTL handling" do
    it "should set expiration time on values" do
      started_at = Time.now.to_f
      storage.set("atproto:test:ttl", "value", ttl: 2)
      finished_at = Time.now.to_f

      database = SQLite3::Database.new(database_path)
      expires_at = database.get_first_value(
        "SELECT expires_at FROM atproto_storage WHERE key = ?",
        ["atproto:test:ttl"]
      )

      expires_at.should be >= started_at + 2
      expires_at.should be <= finished_at + 2
    ensure
      database&.close
    end
  end

  describe "locking" do
    it "should persist the lock only while the block is executing" do
      database = SQLite3::Database.new(database_path)

      storage.with_lock("atproto:test:lock", ttl: 30) do
        locks = database.get_first_value("SELECT COUNT(*) FROM atproto_locks WHERE key = ?", ["atproto:test:lock"])
        locks.should == 1
      end

      locks = database.get_first_value("SELECT COUNT(*) FROM atproto_locks WHERE key = ?", ["atproto:test:lock"])
      locks.should == 0
    ensure
      database&.close
    end

    it "should ensure lock is released even if block raises error" do
      database = SQLite3::Database.new(database_path)

      expect {
        storage.with_lock("atproto:test:lock", ttl: 30) do
          raise "test error"
        end
      }.to raise_error(RuntimeError)

      locks = database.get_first_value("SELECT COUNT(*) FROM atproto_locks WHERE key = ?", ["atproto:test:lock"])
      locks.should == 0
    ensure
      database&.close
    end

    it "should coordinate locks between storage instances" do
      second_storage = AuthProto::Storage::SQLite.new(path: database_path)

      storage.with_lock("atproto:test:lock", ttl: 30) do
        expect {
          second_storage.with_lock("atproto:test:lock", ttl: 30) { true }
        }.to raise_error(AuthProto::Storage::LockError)
      end
    ensure
      second_storage&.close
    end

    it "should not clean a stale lock on exit if it was already replaced" do
      now = Time.utc(2026, 1, 1)
      Time.stubs(:now).returns(now)
      second_storage = AuthProto::Storage::SQLite.new(path: database_path)
      second_thread = nil

      newer_owner_acquired = Queue.new
      release_newer_owner = Queue.new

      storage.with_lock("atproto:test:lock", ttl: 1) do
        Time.stubs(:now).returns(now + 1)

        second_thread = Thread.new do
          second_storage.with_lock("atproto:test:lock", ttl: 30) do
            newer_owner_acquired << true

            # make sure it holds the lock until the test finishes
            release_newer_owner.pop
          end
        end

        # wait until second_thread places a lock
        newer_owner_acquired.pop
      end

      # ensure that storage.with_lock exiting did not delete second_thread's lock
      expect {
        storage.with_lock("atproto:test:lock", ttl: 30) { true }
      }.to raise_error(AuthProto::Storage::LockError)
    ensure
      release_newer_owner << true if release_newer_owner
      second_thread&.join
      second_storage&.close
    end
  end
end
