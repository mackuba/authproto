# frozen_string_literal: true

describe AuthProto::Storage::KeyBuilder do
  describe ".session_key" do
    it "should build valid session key" do
      AuthProto::Storage::KeyBuilder.session_key("123").should == "atproto:session:123"
    end
  end

  describe ".state_key" do
    it "should build valid state key" do
      AuthProto::Storage::KeyBuilder.state_key("xyz789").should == "atproto:state:xyz789"
    end
  end

  describe ".nonce_key" do
    it "should build valid nonce key" do
      AuthProto::Storage::KeyBuilder.nonce_key("example.com").should == "atproto:nonce:example.com"
    end
  end

  describe ".lock_key" do
    it "should build valid lock key" do
      AuthProto::Storage::KeyBuilder.lock_key("session", "123").should == "atproto:lock:session:123"
    end
  end
end
