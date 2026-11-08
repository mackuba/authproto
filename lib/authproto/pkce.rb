# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'securerandom'

require_relative 'errors'

module AuthProto

  #
  # @api private
  #
  # Generates a matching PKCE verifier and S256 challenge for an OAuth authorization flow.
  #

  class PKCE

    # Error raised when generating a verifier/challenge pair fails.
    class Error < AuthProto::Error; end

    # Challenge method required by AT Protocol OAuth.
    CHALLENGE_METHOD_S256 = 'S256'

    # Random bytes providing 256 bits of entropy, encoded as a 43-character verifier without padding.
    VERIFIER_BYTES = 32

    # Cryptographically random, URL-safe code verifier.
    # @return [String]
    attr_reader :verifier

    # Base64URL-encoded SHA-256 digest of the verifier, without padding.
    # @return [String]
    attr_reader :challenge

    # Generates a verifier and its matching S256 challenge.
    #
    # Both strings are frozen so the pair cannot be changed after generation.
    #
    # @raise [Error] if random generation or hashing fails
    #
    def initialize
      @verifier = SecureRandom.urlsafe_base64(VERIFIER_BYTES, false).freeze
      digest = OpenSSL::Digest::SHA256.digest(@verifier)
      @challenge = Base64.urlsafe_encode64(digest, padding: false).freeze
    rescue StandardError => e
      raise Error, "Failed to generate PKCE: #{e.message}"
    end
  end
end
