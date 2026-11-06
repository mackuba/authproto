# frozen_string_literal: true

require_relative 'storage_examples'

describe AuthProto::Storage::Memory do
  let(:storage) { AuthProto::Storage::Memory.new }

  include_examples "a storage implementation"

  describe "#cleanup_expired_records" do
    it "should remove expired values and locks without accessing their keys" do
      now = Time.utc(2026, 1, 1)
      Time.stubs(:now).returns(now)
      storage.set('atproto:expired', 'expired', ttl: 1)
      storage.set('atproto:live', 'live', ttl: 60)
      storage.set('atproto:permanent', 'permanent')
      storage.send(:acquire_lock, 'atproto:expired-lock', ttl: 1)
      storage.send(:acquire_lock, 'atproto:live-lock', ttl: 60)

      Time.stubs(:now).returns(now + 1)
      storage.cleanup_expired_records
      storage.cleanup_expired_records

      storage.instance_variable_get(:@data).keys.sort.should == ['atproto:live', 'atproto:permanent']
      storage.instance_variable_get(:@expirations).keys.should == ['atproto:live']
      storage.instance_variable_get(:@locks).keys.should == ['lock:atproto:live-lock']
      storage.get('atproto:live').should == 'live'
      storage.get('atproto:permanent').should == 'permanent'

      expect {
        storage.with_lock('atproto:live-lock') { true }
      }.to raise_error(AuthProto::Storage::LockError)
    end
  end

  describe "memory-specific behavior" do
    it "should clear an existing expiry when overwriting without a TTL" do
      now = Time.utc(2026, 1, 1)
      Time.stubs(:now).returns(now)
      storage.set('atproto:test', 'pending', ttl: 900)
      storage.set('atproto:test', 'authenticated', ttl: nil)

      Time.stubs(:now).returns(now + 901)
      storage.get('atproto:test').should == 'authenticated'
    end

    it "should clean up expired keys automatically" do
      now = Time.utc(2026, 1, 1)
      Time.stubs(:now).returns(now)
      storage.set("atproto:test:short", "value", ttl: 1)
      storage.set("atproto:test:long", "value", ttl: 3600)

      storage.get("atproto:test:short").should == "value"
      Time.stubs(:now).returns(now + 1)
      storage.get("atproto:test:short").should be_nil
      storage.get("atproto:test:long").should == "value"
    end

    it "should handle clear operation" do
      storage.set("atproto:test:1", "value1")
      storage.set("atproto:test:2", "value2")

      storage.clear

      storage.get("atproto:test:1").should be_nil
      storage.get("atproto:test:2").should be_nil
    end
  end
end
