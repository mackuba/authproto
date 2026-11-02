# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'securerandom'

describe AuthProto::Encryption do
  describe "without ATPROTO_MASTER_KEY" do
    before do
      @original_master_key = ENV.delete("ATPROTO_MASTER_KEY")
    end

    after do
      ENV["ATPROTO_MASTER_KEY"] = @original_master_key
    end

    it "should decrypt data using a separately created encryption service" do
      first = AuthProto::Encryption::Service.new
      encrypted = first.encrypt("access token", context: "data.access_token")
      second = AuthProto::Encryption::Service.new

      second.decrypt(encrypted, context: "data.access_token").should == "access token"
    end

    it "should generate the fallback key only once across key providers" do
      provider_class = Class.new(AuthProto::Encryption::KeyProvider)
      SecureRandom.expects(:random_bytes).with(32).once.returns("x" * 32)

      expect {
        first = provider_class.new
        second = provider_class.new
        second.key_for_context("test").should == first.key_for_context("test")
      }.to output(/Using randomly generated encryption key/).to_stderr
    end

    it "should roundtrip a session with nested tokens through separate serializers" do
      session = AuthProto::State::Session.new(client_id: "test-client", scope: "atproto")
      session.tokens = AuthProto::State::TokenSet.new(
        access_token: "access", refresh_token: "refresh", token_type: "DPoP",
        expires_in: 3600, scope: "atproto", sub: "did:plc:alice"
      )

      serialized = AuthProto::Serialization::Session.new.serialize(session)
      restored = AuthProto::Serialization::Session.new.deserialize(serialized)

      restored.pkce_verifier.should == session.pkce_verifier
      restored.tokens.access_token.should == "access"
      restored.tokens.refresh_token.should == "refresh"
    end

    it "should prefer an explicit environment key even after a fallback key was generated" do
      AuthProto::Encryption::KeyProvider.new
      ENV["ATPROTO_MASTER_KEY"] = Base64.strict_encode64("y" * 32)
      configured = AuthProto::Encryption::KeyProvider.new
      expected = AuthProto::Encryption::HKDF.derive(
        "y" * 32, salt: OpenSSL::Digest.digest("SHA256", "atproto-salt-test"), info: "atproto-test", length: 32
      )

      configured.key_for_context("test").should == expected
    end
  end

  describe AuthProto::Encryption::Service do
    let(:encryption_service) { AuthProto::Encryption::Service.new }
    let(:sample_data) { "sensitive data" }
    let(:context) { "access_token" }

    describe "#encrypt" do
      it "should encrypt data with a context" do
        result = encryption_service.encrypt(sample_data, context: context)

        result[:version].should == AuthProto::Encryption::VERSION
        result[:iv].should be_a(String)
        result[:data].should be_a(String)
        result[:tag].should be_a(String)

        # Base64 validation
        (Base64.strict_decode64(result[:iv])).should be_truthy
        (Base64.strict_decode64(result[:data])).should be_truthy
        (Base64.strict_decode64(result[:tag])).should be_truthy
      end

      it "should produce different ciphertexts for same data with different contexts" do
        result1 = encryption_service.encrypt(sample_data, context: "context1")
        result2 = encryption_service.encrypt(sample_data, context: "context2")

        result2[:data].should_not == result1[:data]
      end

      it "should produce different ciphertexts for same data and context due to IV" do
        result1 = encryption_service.encrypt(sample_data, context: context)
        result2 = encryption_service.encrypt(sample_data, context: context)

        result2[:data].should_not == result1[:data]
        result2[:iv].should_not == result1[:iv]
      end

      it "should raise EncryptionError for nil data" do
        expect {
          encryption_service.encrypt(nil, context: context)
        }.to raise_error(AuthProto::Encryption::EncryptionError)
      end

      it "should raise EncryptionError for nil context" do
        expect {
          encryption_service.encrypt(sample_data, context: nil)
        }.to raise_error(AuthProto::Encryption::EncryptionError)
      end

      it "should raise EncryptionError for empty context" do
        expect {
          encryption_service.encrypt(sample_data, context: "")
        }.to raise_error(AuthProto::Encryption::EncryptionError)
      end

      it "should convert non-string data to string" do
        result = encryption_service.encrypt(123, context: context)
        decrypted = encryption_service.decrypt(result, context: context)
        decrypted.should == "123"
      end
    end

    describe "#decrypt" do
      it "should correctly decrypt encrypted data" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        decrypted = encryption_service.decrypt(encrypted, context: context)

        decrypted.should == sample_data
      end

      it "should raise DecryptionError for wrong context" do
        encrypted = encryption_service.encrypt(sample_data, context: context)

        expect {
          encryption_service.decrypt(encrypted, context: "wrong_context")
        }.to raise_error(AuthProto::Encryption::DecryptionError)
      end

      it "should raise DecryptionError for tampered data" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        encrypted[:data] = Base64.strict_encode64("tampered")

        expect {
          encryption_service.decrypt(encrypted, context: context)
        }.to raise_error(AuthProto::Encryption::DecryptionError)
      end

      it "should raise DecryptionError for tampered auth tag" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        encrypted[:tag] = Base64.strict_encode64("tampered")

        expect {
          encryption_service.decrypt(encrypted, context: context)
        }.to raise_error(AuthProto::Encryption::DecryptionError)
      end

      (0...16).each do |length|
        it "should reject an authentic tag truncated to #{length} bytes" do
          encrypted = encryption_service.encrypt(sample_data, context: context)
          tag = Base64.strict_decode64(encrypted[:tag])
          encrypted[:tag] = Base64.strict_encode64(tag.byteslice(0, length))

          expect {
            encryption_service.decrypt(encrypted, context: context)
          }.to raise_error(AuthProto::Encryption::DecryptionError, /Authentication tag must be 16 bytes/)
        end
      end

      it "should reject an authentication tag longer than 16 bytes" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        tag = Base64.strict_decode64(encrypted[:tag])
        encrypted[:tag] = Base64.strict_encode64(tag + "\x00")

        expect {
          encryption_service.decrypt(encrypted, context: context)
        }.to raise_error(AuthProto::Encryption::DecryptionError, /Authentication tag must be 16 bytes/)
      end

      it "should raise DecryptionError for nil encrypted data" do
        expect {
          encryption_service.decrypt(nil, context: context)
        }.to raise_error(AuthProto::Encryption::DecryptionError)
      end

      it "should raise DecryptionError for nil context" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        expect {
          encryption_service.decrypt(encrypted, context: nil)
        }.to raise_error(AuthProto::Encryption::DecryptionError)
      end

      it "should raise DecryptionError for invalid format" do
        expect {
          encryption_service.decrypt({ invalid: "format" }, context: context)
        }.to raise_error(AuthProto::Encryption::DecryptionError)
      end

      it "should raise DecryptionError for wrong version" do
        encrypted = encryption_service.encrypt(sample_data, context: context)
        encrypted[:version] = 999

        expect {
          encryption_service.decrypt(encrypted, context: context)
        }.to raise_error(AuthProto::Encryption::DecryptionError)
      end
    end
  end

  describe AuthProto::Encryption::KeyProvider do
    let(:key_provider) { AuthProto::Encryption::KeyProvider.new }

    describe "#initialize" do
      before do
        @original_master_key = ENV['ATPROTO_MASTER_KEY']
      end

      after do
        ENV['ATPROTO_MASTER_KEY'] = @original_master_key
      end

      [0, 1, 16, 31, 33, 64].each do |length|
        it "should reject a master key that decodes to #{length} bytes" do
          ENV['ATPROTO_MASTER_KEY'] = Base64.strict_encode64(SecureRandom.random_bytes(length))

          expect {
            described_class.new
          }.to raise_error(AuthProto::Encryption::ConfigurationError, /must decode to exactly 32 bytes/)
        end
      end

      it "should accept a Base64-encoded 32-byte binary master key" do
        key = "\xFF".b * 32
        ENV['ATPROTO_MASTER_KEY'] = Base64.strict_encode64(key)
        expected = AuthProto::Encryption::HKDF.derive(
          key, salt: OpenSSL::Digest.digest('SHA256', 'atproto-salt-test'), info: 'atproto-test', length: 32
        )

        described_class.new.key_for_context('test').should == expected
      end

      it "should reject malformed Base64 even when its encoded length looks valid" do
        ENV['ATPROTO_MASTER_KEY'] = '!' * 44

        expect { described_class.new }.to raise_error(ArgumentError, /invalid base64/)
      end
    end

    describe "#key_for_context" do
      it "should derive different keys for different contexts" do
        key1 = key_provider.key_for_context("context1")
        key2 = key_provider.key_for_context("context2")

        key2.should_not == key1
      end

      it "should derive consistent keys for same context" do
        key1 = key_provider.key_for_context("context")
        key2 = key_provider.key_for_context("context")

        key2.should == key1
      end

      it "should return keys of correct length for AES-256" do
        key = key_provider.key_for_context("context")
        key.bytesize.should == 32
      end

      it "should raise ConfigurationError for nil context" do
        expect {
          key_provider.key_for_context(nil)
        }.to raise_error(AuthProto::Encryption::ConfigurationError)
      end
    end
  end
end
