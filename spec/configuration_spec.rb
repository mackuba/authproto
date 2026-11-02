# frozen_string_literal: true

require 'logger'

describe AuthProto::Configuration do
  let(:configuration) { AuthProto::Configuration.new }

  describe "#initialize" do
    it "should set default values" do
      configuration.client_assertion_lifetime.should == 300
      configuration.dpop_nonce_lifetime.should == 300
      configuration.pending_session_ttl.should == 900
      configuration.logger.should be_an_instance_of(Logger)
      configuration.storage.should be_an_instance_of(AuthProto::Storage::Memory)
    end
  end

  describe "#validate" do
    it "should accept a positive client assertion lifetime above five minutes" do
      configuration.client_assertion_lifetime = 600
      configuration.validate.should be true
    end

    [nil, 0, -1, 1.5, '300', false].each do |lifetime|
      it "should reject an invalid client assertion lifetime #{lifetime.inspect}" do
        configuration.client_assertion_lifetime = lifetime

        expect {
          configuration.validate
        }.to raise_error(AuthProto::ConfigurationError, "Client assertion lifetime must be a positive integer")
      end
    end

    it "should accept a custom positive DPoP nonce lifetime" do
      configuration.dpop_nonce_lifetime = 120
      configuration.validate.should be true
    end

    [nil, 0, -1, 1.5, '300'].each do |lifetime|
      it "should reject an invalid DPoP nonce lifetime #{lifetime.inspect}" do
        configuration.dpop_nonce_lifetime = lifetime

        expect {
          configuration.validate
        }.to raise_error(AuthProto::ConfigurationError, "DPoP nonce lifetime must be a positive integer")
      end
    end

    it "should accept a custom positive pending session TTL" do
      configuration.pending_session_ttl = 1800
      configuration.validate.should be true
      configuration.pending_session_ttl.should == 1800
    end

    [nil, 0, -1, 1.5, '900'].each do |ttl|
      it "should reject an invalid pending session TTL #{ttl.inspect}" do
        configuration.pending_session_ttl = ttl

        expect {
          configuration.validate
        }.to raise_error(AuthProto::ConfigurationError, "Pending session TTL must be a positive integer")
      end
    end

    it "should validate valid configuration" do
      configuration.validate.should be true
    end

    it "should validate custom storage implementation" do
      custom_storage = Class.new(AuthProto::Storage::Interface) do
        def set(key, value, ttl: nil); end
        def get(key); end
        def delete(key); end
        def exists?(key); end
        def with_lock(key, ttl: 30); end
      end.new

      configuration.storage = custom_storage
      configuration.validate.should be true
    end

    it "should raise error for invalid storage implementation" do
      configuration.storage = Object.new
      expect {
        configuration.validate
      }.to raise_error(AuthProto::ConfigurationError)
    end

    it "should raise error for nil storage" do
      configuration.storage = nil
      expect {
        configuration.validate
      }.to raise_error(AuthProto::ConfigurationError)
    end

    it "should validate http client interface" do
      valid_client = Object.new
      def valid_client.get(url, headers = {}); end
      def valid_client.post(url, body: nil, headers: {}); end

      configuration.http_client = valid_client
      configuration.validate.should be true
    end

    it "should raise error for invalid http client" do
      configuration.http_client = Object.new
      expect {
        configuration.validate
      }.to raise_error(AuthProto::ConfigurationError)
    end
  end
end
