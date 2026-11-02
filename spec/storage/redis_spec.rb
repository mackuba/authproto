# frozen_string_literal: true

require_relative 'storage_examples'

describe AuthProto::Storage::Redis do
  let(:redis) { Redis.new(url: ENV.fetch("REDIS_URL")) }
  let(:storage) { AuthProto::Storage::Redis.new(redis_client: redis) }

  # Include shared storage implementation tests
  include_examples "a storage implementation"

  # Redis expiration uses the server's clock rather than Ruby's clock.
  def advance_storage_time(seconds)
    sleep seconds
  end

  unless ENV["REDIS_URL"]
    warn "** Set REDIS_URL to run Redis storage tests"
  end

  before do
    skip "Set REDIS_URL to run Redis storage specs" unless ENV["REDIS_URL"]

    # Clear test keys before each test
    keys = redis.keys("atproto:*")
    redis.del(*keys) if keys.any?
  end

  describe "#initialize" do
    it "should accept a custom redis client" do
      custom_redis = Redis.new
      storage = AuthProto::Storage::Redis.new(redis_client: custom_redis)
      storage.instance_variable_get(:@redis_client).should == custom_redis
    end

    it "should create default redis client if none provided" do
      storage = AuthProto::Storage::Redis.new
      storage.instance_variable_get(:@redis_client).should be_an_instance_of(Redis)
    end
  end

  describe "error handling" do
    it "should wrap Redis connection errors" do
      redis.stubs(:set).raises(Redis::ConnectionError)
      expect {
        storage.set("atproto:test:key", "value")
      }.to raise_error(AuthProto::Storage::Redis::RedisError)
    end

    it "should wrap Redis command errors" do
      redis.stubs(:get).raises(Redis::CommandError)
      expect {
        storage.get("atproto:test:key")
      }.to raise_error(AuthProto::Storage::Redis::RedisError)
    end
  end

  describe "TTL handling" do
    it "should set TTL on values" do
      storage.set("atproto:test:ttl", "value", ttl: 2)
      ttl = redis.ttl("atproto:test:ttl")
      ttl.should be >= 1
      ttl.should be <= 2
    end
  end

  describe "locking" do
    after do
      # Clean up any leftover locks
      redis.del("atproto:locks:atproto:test:lock") if ENV["REDIS_URL"]
    end

    it "should create lock with correct key prefix" do
      storage.with_lock("atproto:test:lock", ttl: 30) do
        (redis.exists?("atproto:locks:atproto:test:lock")).should be_truthy
      end
    end

    it "should ensure lock is released after block execution" do
      executed = false
      storage.with_lock("atproto:test:lock", ttl: 30) do
        executed = true
      end

      (executed).should be_truthy
      (redis.exists?("atproto:locks:atproto:test:lock")).should be_falsey
    end

    it "should ensure lock is released even if block raises error" do
      expect {
        storage.with_lock("atproto:test:lock", ttl: 30) do
          raise "test error"
        end
      }.to raise_error(RuntimeError)

      (redis.exists?("atproto:locks:atproto:test:lock")).should be_falsey
    end

    it "should release lock if Redis connection fails during block execution" do
      redis.stubs(:del).raises(Redis::ConnectionError)
      expect {
        storage.with_lock("atproto:test:lock", ttl: 30) { true }
      }.to raise_error(AuthProto::Storage::Redis::RedisError)
    ensure
      redis.unstub(:del) if ENV["REDIS_URL"]
    end
  end
end
