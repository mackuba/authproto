# frozen_string_literal: true

describe AuthProto::DPoP::NonceManager do
  let(:server_url) { "https://example.com" }
  let(:invalid_server_url) { "http://example.com" }
  let(:nonce) { "valid_nonce" }
  let(:expired_nonce) { "expired_nonce" }
  let(:ttl) { 2 } # Custom TTL for testing expiration
  let(:nonce_manager) { AuthProto::DPoP::NonceManager.new(ttl: ttl) }

  after do
    nonce_manager.clear(server_url)
  end

  describe "#initialize" do
    it "should initialize with a default TTL" do
      manager = AuthProto::DPoP::NonceManager.new
      manager.instance_variable_get(:@ttl).should == AuthProto::DPoP::NonceManager::DEFAULT_TTL
    end

    it "should initialize with a custom TTL" do
      nonce_manager.instance_variable_get(:@ttl).should == ttl
    end
  end

  describe "#update" do
    it "should store a nonce for a server" do
      nonce_manager.update(nonce: nonce, server_url: server_url)
      stored = nonce_manager.get(server_url)
      stored.should == nonce
    end

    it "should update an existing nonce" do
      nonce_manager.update(nonce: nonce, server_url: server_url)
      nonce_manager.update(nonce: "new_nonce", server_url: server_url)
      nonce_manager.get(server_url).should == "new_nonce"
    end

    it "should store nonce for non-HTTPS localhost server" do
      nonce_manager.update(nonce: nonce, server_url: "http://localhost:3000")
      stored = nonce_manager.get("http://localhost:3000")
      stored.should == nonce
    end

    it "should raise an error if nonce is invalid" do
      expect {
        nonce_manager.update(nonce: "", server_url: server_url)
      }.to raise_error(AuthProto::DPoP::NonceManager::NonceError)
    end

    it "should raise an error if server_url is invalid" do
      expect {
        nonce_manager.update(nonce: nonce, server_url: invalid_server_url)
      }.to raise_error(AuthProto::DPoP::NonceManager::NonceError)
    end
  end

  describe "#get" do
    it "should return the current nonce for a server" do
      nonce_manager.update(nonce: nonce, server_url: server_url)
      nonce_manager.get(server_url).should == nonce
    end

    it "should return nil if no nonce exists for the server" do
      nonce_manager.get(server_url).should be_nil
    end

    it "should return nil if the nonce has expired" do
      nonce_manager.update(nonce: expired_nonce, server_url: server_url)
      sleep(ttl + 0.1) # Wait for expiration
      nonce_manager.get(server_url).should be_nil
    end

    it "should raise an error if server_url is invalid" do
      expect {
        nonce_manager.get("")
      }.to raise_error(AuthProto::DPoP::NonceManager::NonceError)
    end
  end

  describe "#clear" do
    it "should remove a nonce for a server" do
      nonce_manager.update(nonce: nonce, server_url: server_url)
      nonce_manager.clear(server_url)
      nonce_manager.get(server_url).should be_nil
    end
  end

  describe "thread safety" do
    it "should handle concurrent nonce updates" do
      threads = 10.times.map do |i|
        Thread.new do
          nonce_manager.update(nonce: "nonce_#{i}", server_url: server_url)
          sleep(0.1)
          nonce_manager.get(server_url)
        end
      end

      threads.each(&:join)
      # The nonce should exist and be one of the values we set
      stored = nonce_manager.get(server_url)
      (stored =~ /^nonce_\d$/).should be_truthy
    end
  end
end
