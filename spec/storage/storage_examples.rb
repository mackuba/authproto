# frozen_string_literal: true

shared_examples "a storage implementation" do
  def advance_storage_time(seconds)
    now = Time.now
    Time.stubs(:now).returns(now + seconds)
  end

  describe "basic operations" do
    it "should store and retrieve values" do
      storage.set("atproto:test:key", "value")
      storage.get("atproto:test:key").should == "value"
    end

    it "should handle nil values" do
      storage.set("atproto:test:nil", nil)
      storage.get("atproto:test:nil").should be_nil
    end

    it "should return nil for missing keys" do
      storage.get("atproto:test:missing").should be_nil
    end

    it "should delete values" do
      storage.set("atproto:test:delete", "value")
      (storage.delete("atproto:test:delete")).should be_truthy
      storage.get("atproto:test:delete").should be_nil
    end

    it "should check existence" do
      storage.set("atproto:test:exists", "value")
      (storage.exists?("atproto:test:exists")).should be_truthy
      (storage.exists?("atproto:test:missing")).should be_falsey
    end
  end

  describe "key validation" do
    it "should require atproto: prefix" do
      expect {
        storage.set("invalid:key", "value")
      }.to raise_error(AuthProto::Storage::StorageError)
    end

    it "should reject nil keys" do
      expect {
        storage.set(nil, "value")
      }.to raise_error(AuthProto::Storage::StorageError)
    end

    it "should reject empty keys" do
      expect {
        storage.set("", "value")
      }.to raise_error(AuthProto::Storage::StorageError)
    end

    it "should reject non-string keys" do
      expect {
        storage.set(123, "value")
      }.to raise_error(AuthProto::Storage::StorageError)
    end
  end

  describe "TTL handling" do
    it "should expire values after TTL" do
      Time.stubs(:now).returns(Time.utc(2026, 1, 1))
      storage.set("atproto:test:ttl", "value", ttl: 1)
      storage.get("atproto:test:ttl").should == "value"
      advance_storage_time(1.1)
      storage.get("atproto:test:ttl").should be_nil
    end

    it "should validate TTL values" do
      expect {
        storage.set("atproto:test:ttl", "value", ttl: -1)
      }.to raise_error(AuthProto::Storage::StorageError)

      expect {
        storage.set("atproto:test:ttl", "value", ttl: "invalid")
      }.to raise_error(AuthProto::Storage::StorageError)
    end

    it "should handle nil TTL" do
      storage.set("atproto:test:ttl", "value", ttl: nil)
      storage.get("atproto:test:ttl").should == "value"
    end
  end

  describe "locking" do
    it "should execute blocks with locks" do
      result = storage.with_lock("atproto:test:lock", ttl: 30) do
        "success"
      end

      result.should == "success"
      (storage.with_lock("atproto:test:lock", ttl: 30) { true }).should be_truthy
    end

    it "should expire locks after TTL" do
      Time.stubs(:now).returns(Time.utc(2026, 1, 1))

      storage.with_lock("atproto:test:lock", ttl: 1) do
        expect {
          storage.with_lock("atproto:test:lock", ttl: 30) { true }
        }.to raise_error(AuthProto::Storage::LockError)

        advance_storage_time(1.1)
        (storage.with_lock("atproto:test:lock", ttl: 30) { true }).should be_truthy
      end
    end

    it "should release locks after block even if error raised" do
      expect {
        storage.with_lock("atproto:test:lock", ttl: 30) do
          raise "test error"
        end
      }.to raise_error(RuntimeError)

      (storage.with_lock("atproto:test:lock", ttl: 30) { true }).should be_truthy
    end

    it "should require block for with_lock" do
      expect {
        storage.with_lock("atproto:test:lock", ttl: 30)
      }.to raise_error(ArgumentError)
    end
  end

  describe "concurrency" do
    it "should handle concurrent access to same key" do
      threads = 10.times.map do
        Thread.new do
          storage.set("atproto:test:concurrent", "value")
          storage.get("atproto:test:concurrent")
          storage.delete("atproto:test:concurrent")
        end
      end

      threads.each(&:join)
      storage.get("atproto:test:concurrent").should be_nil
    end

    it "should handle concurrent lock acquisition" do
      success_count = 0
      fail_count = 0

      threads = 10.times.map do
        Thread.new do
          begin
            storage.with_lock("atproto:test:lock", ttl: 30) do
              success_count += 1
              sleep 0.1
            end
          rescue AuthProto::Storage::LockError
            fail_count += 1
          end
        end
      end

      threads.each(&:join)
      success_count.should == 1
      fail_count.should == 9
    end
  end
end
