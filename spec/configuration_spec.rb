# frozen_string_literal: true

require 'logger'

describe AuthProto::Configuration do
  let(:configuration) { AuthProto::Configuration.new }

  describe "#initialize" do
    it "should set default values" do
      configuration.default_token_lifetime.should == 300
      configuration.dpop_nonce_lifetime.should == 300
      configuration.logger.should be_an_instance_of(Logger)
      configuration.storage.should be_an_instance_of(AuthProto::Storage::Memory)
    end
  end

  describe "#validate" do
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
