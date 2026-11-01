# frozen_string_literal: true

describe AuthProto::DPoP::NonceManager do
  let(:session_id) { 'session-1' }
  let(:server_url) { "https://example.com" }
  let(:invalid_server_url) { "http://example.com" }
  let(:nonce) { "valid_nonce" }
  let(:expired_nonce) { "expired_nonce" }
  let(:ttl) { 2 } # Custom TTL for testing expiration
  let(:nonce_manager) { AuthProto::DPoP::NonceManager.new(ttl: ttl) }

  after do
    nonce_manager.clear(server_url: server_url, session_id: session_id)
  end

  describe "#initialize" do
    it "should initialize with a default TTL" do
      manager = AuthProto::DPoP::NonceManager.new
      manager.instance_variable_get(:@ttl).should == 300
    end

    it "should initialize with a custom TTL" do
      nonce_manager.instance_variable_get(:@ttl).should == ttl
    end

    [nil, 2].each do |override|
      it "should expire stored nonces using #{override ? 'an explicit TTL override' : 'the configured lifetime'}" do
        now = Time.utc(2026, 1, 1)
        Time.stubs(:now).returns(now)
        AuthProto.stubs(:storage).returns(AuthProto::Storage::Memory.new)
        AuthProto.configuration.stubs(:dpop_nonce_lifetime).returns(7)
        manager = AuthProto::DPoP::NonceManager.new(ttl: override)
        manager.update(session_id: session_id, nonce: nonce, server_url: server_url)
        lifetime = override || 7

        Time.stubs(:now).returns(now + lifetime - 1)
        manager.get(server_url: server_url, session_id: session_id).should == nonce
        Time.stubs(:now).returns(now + lifetime)
        manager.get(server_url: server_url, session_id: session_id).should be_nil
      end
    end
  end

  describe "#update" do
    ['has space', "has\ttab", "has\nnewline", 'has"quote', 'has\\slash',
     "\x7F", 'é', 'nonce'.encode('UTF-16LE'), 123, ['one', 'two'], "\xFF"].each do |value|
      it "should reject malformed nonce #{value.inspect} without overwriting the cached nonce" do
        nonce_manager.update(session_id: session_id, nonce: nonce, server_url: server_url)

        expect {
          nonce_manager.update(session_id: session_id, nonce: value, server_url: server_url)
        }.to raise_error(AuthProto::DPoP::NonceManager::NonceError, /Invalid.*DPoP nonce/)

        nonce_manager.get(server_url: server_url, session_id: session_id).should == nonce
      end
    end

    [nil, ''].each do |value|
      it "should reject a nonce of #{value.inspect} without overwriting the cached nonce" do
        nonce_manager.update(session_id: session_id, nonce: nonce, server_url: server_url)

        expect {
          nonce_manager.update(session_id: session_id, nonce: value, server_url: server_url)
        }.to raise_error(AuthProto::DPoP::NonceManager::NonceError, /nonce must not be empty/)

        nonce_manager.get(server_url: server_url, session_id: session_id).should == nonce
      end
    end

    it "should accept all NQCHAR characters, including commas, without changing them" do
      value = ((0x21..0x7E).map(&:chr) - ['"', '\\']).join
      nonce_manager.update(session_id: session_id, nonce: value, server_url: server_url)

      nonce_manager.get(server_url: server_url, session_id: session_id).should == value
    end

    it "should store a nonce for a server" do
      nonce_manager.update(session_id: session_id, nonce: nonce, server_url: server_url)
      stored = nonce_manager.get(server_url: server_url, session_id: session_id)
      stored.should == nonce
    end

    it "should update an existing nonce" do
      nonce_manager.update(session_id: session_id, nonce: nonce, server_url: server_url)
      nonce_manager.update(session_id: session_id, nonce: "new_nonce", server_url: server_url)
      nonce_manager.get(server_url: server_url, session_id: session_id).should == "new_nonce"
    end

    it "should store nonce for non-HTTPS localhost server" do
      nonce_manager.update(session_id: session_id, nonce: nonce, server_url: "http://localhost:3000")
      stored = nonce_manager.get(server_url: "http://localhost:3000", session_id: session_id)
      stored.should == nonce
    end

    it "should raise an error if nonce is invalid" do
      expect {
        nonce_manager.update(session_id: session_id, nonce: "", server_url: server_url)
      }.to raise_error(AuthProto::DPoP::NonceManager::NonceError)
    end

    it "should raise an error if server_url is invalid" do
      expect {
        nonce_manager.update(session_id: session_id, nonce: nonce, server_url: invalid_server_url)
      }.to raise_error(AuthProto::DPoP::NonceManager::NonceError)
    end
  end

  describe "#get" do
    it "should return the current nonce for a server" do
      nonce_manager.update(session_id: session_id, nonce: nonce, server_url: server_url)
      nonce_manager.get(server_url: server_url, session_id: session_id).should == nonce
    end

    it "should return nil if no nonce exists for the server" do
      nonce_manager.get(server_url: server_url, session_id: session_id).should be_nil
    end

    it "should return nil if the nonce has expired" do
      nonce_manager.update(session_id: session_id, nonce: expired_nonce, server_url: server_url)
      sleep(ttl + 0.1) # Wait for expiration
      nonce_manager.get(server_url: server_url, session_id: session_id).should be_nil
    end

    it "should raise an error if server_url is invalid" do
      expect {
        nonce_manager.get(server_url: "", session_id: session_id)
      }.to raise_error(AuthProto::DPoP::NonceManager::NonceError)
    end
  end

  describe "#clear" do
    it "should remove a nonce for a server" do
      nonce_manager.update(session_id: session_id, nonce: nonce, server_url: server_url)
      nonce_manager.clear(server_url: server_url, session_id: session_id)
      nonce_manager.get(server_url: server_url, session_id: session_id).should be_nil
    end
  end

  describe "session and server isolation" do
    before do
      AuthProto.stubs(:storage).returns(AuthProto::Storage::Memory.new)
    end

    it "should isolate sessions and origins while sharing endpoints on the same origin" do
      nonce_manager.update(nonce: 'first', server_url: "#{server_url}:443/par", session_id: session_id)
      nonce_manager.update(nonce: 'second', server_url: server_url, session_id: 'session-2')
      nonce_manager.update(nonce: 'other-server', server_url: 'https://other.example.com', session_id: session_id)
      nonce_manager.update(nonce: 'other-port', server_url: "#{server_url}:8443", session_id: session_id)

      nonce_manager.get(server_url: "#{server_url}/token?x=1", session_id: session_id).should == 'first'
      nonce_manager.get(server_url: server_url, session_id: 'session-2').should == 'second'
      nonce_manager.get(server_url: 'https://other.example.com', session_id: session_id).should == 'other-server'
      nonce_manager.get(server_url: "#{server_url}:8443", session_id: session_id).should == 'other-port'

      nonce_manager.clear(server_url: "#{server_url}/different-path", session_id: session_id)
      nonce_manager.get(server_url: server_url, session_id: session_id).should be_nil
      nonce_manager.get(server_url: server_url, session_id: 'session-2').should == 'second'
      nonce_manager.get(server_url: 'https://other.example.com', session_id: session_id).should == 'other-server'
      nonce_manager.get(server_url: "#{server_url}:8443", session_id: session_id).should == 'other-port'
    end

    it "should restore the scoped nonce through a new manager" do
      nonce_manager.update(nonce: nonce, server_url: server_url, session_id: session_id)
      restored = described_class.new(ttl: ttl)

      restored.get(server_url: server_url, session_id: session_id).should == nonce
      restored.get(server_url: server_url, session_id: 'session-2').should be_nil
    end

    it "should ignore legacy per-server nonce entries" do
      AuthProto.storage.set("atproto:nonce:#{server_url}", 'old-cache-entry')

      nonce_manager.get(server_url: server_url, session_id: session_id).should be_nil
    end

    [nil, '', 123, false].each do |invalid_id|
      it "should reject an invalid session ID #{invalid_id.inspect} for all operations" do
        expect {
          nonce_manager.get(server_url: server_url, session_id: invalid_id)
        }.to raise_error(described_class::NonceError, /session_id/)
        expect {
          nonce_manager.update(nonce: nonce, server_url: server_url, session_id: invalid_id)
        }.to raise_error(described_class::NonceError, /session_id/)
        expect {
          nonce_manager.clear(server_url: server_url, session_id: invalid_id)
        }.to raise_error(described_class::NonceError, /session_id/)
      end
    end
  end

  describe "thread safety" do
    it "should handle concurrent nonce updates" do
      threads = 10.times.map do |i|
        Thread.new do
          nonce_manager.update(session_id: session_id, nonce: "nonce_#{i}", server_url: server_url)
          sleep(0.1)
          nonce_manager.get(server_url: server_url, session_id: session_id)
        end
      end

      threads.each(&:join)
      # The nonce should exist and be one of the values we set
      stored = nonce_manager.get(server_url: server_url, session_id: session_id)
      (stored =~ /^nonce_\d$/).should be_truthy
    end
  end
end
