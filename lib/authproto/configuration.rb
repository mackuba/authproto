# frozen_string_literal: true

require 'logger'

require_relative 'errors'
require_relative 'storage/interface'

module AuthProto
  class << self

    # Global settings object, replaced without validation.
    #
    # @param value [Configuration] replacement global settings
    # @return [Configuration]
    #
    attr_writer :configuration

    # Returns the process-wide configuration, creating defaults on first access.
    #
    # The default storage is in memory; `http_client` is initially `nil` and must be
    # configured before discovery or OAuth requests.
    #
    # @return [Configuration] current global settings
    #
    def configuration
      @configuration ||= Configuration.new
    end

    # Yields the global configuration, validates it, and returns it.
    #
    # Changes remain on the global object even if validation fails.
    #
    # @yield [config] block that changes settings
    # @yieldparam config [Configuration] mutable global settings
    # @yieldreturn [Object] ignored
    # @return [Configuration] validated global settings
    # @raise [ConfigurationError] if storage, HTTP transport or lifetime settings are invalid
    # @example Configure the default transport
    #   AuthProto.configure do |config|
    #     config.http_client = AuthProto::HTTPClient.new
    #   end
    #
    def configure
      yield(configuration)
      configuration.validate
      configuration
    end

    # Gets the configured storage backend
    # @return [Storage::Interface] The configured storage implementation
    def storage
      configuration.storage
    end

    # Replaces the global configuration with a fresh set of defaults.
    # Existing client instances and their dependencies are not rebuilt.
    #
    # @return [Configuration] new global settings
    #
    def reset_configuration
      @configuration = Configuration.new
    end
  end

  # Raised when global configuration settings are invalid.
  class ConfigurationError < Error; end

  #
  # Configuration class for global AuthProto settings
  #

  class Configuration

    # Default stored nonce lifetime in seconds; used when creating nonce managers without an explicit TTL.
    # @return [Integer] positive lifetime in seconds; defaults to 300
    attr_accessor :dpop_nonce_lifetime

    # Transport used for discovery, PAR and token requests; initially `nil`.
    # @return [#get, #post, nil]
    attr_accessor :http_client

    # Logger used for diagnostics; defaults to standard output.
    # @return [Logger]
    attr_accessor :logger

    # Lifetime of pending authorization attempts in seconds; defaults to 900 (15 minutes).
    # @return [Integer] positive lifetime in seconds
    attr_accessor :pending_session_ttl

    # Storage backend; defaults to a new {Storage::Memory}.
    # @return [Storage::Interface]
    attr_accessor :storage

    # Creates default settings with in-memory storage and no HTTP transport.
    #
    def initialize
      @dpop_nonce_lifetime = 300  # 5 minutes
      @pending_session_ttl = 900  # 15 minutes
      @http_client = nil
      @logger = Logger.new($stdout)
      @storage = AuthProto::Storage::Memory.new
    end

    # Checks storage and transport interfaces and positive nonce and pending session lifetimes.
    #
    # A `nil` HTTP client is accepted, but cannot perform OAuth or discovery requests.
    #
    # @return [true] if validation succeeds
    # @raise [ConfigurationError] if storage, HTTP transport or lifetime settings are invalid
    #
    def validate
      validate_storage
      validate_http_client
      validate_dpop_nonce_lifetime
      validate_pending_session_ttl
      true
    end


    private

    def validate_dpop_nonce_lifetime
      return if @dpop_nonce_lifetime.is_a?(Integer) && @dpop_nonce_lifetime.positive?

      raise ConfigurationError, "DPoP nonce lifetime must be a positive integer"
    end

    def validate_pending_session_ttl
      return if @pending_session_ttl.is_a?(Integer) && @pending_session_ttl.positive?

      raise ConfigurationError, "Pending session TTL must be a positive integer"
    end

    def validate_storage
      raise ConfigurationError, "Storage must be configured" if @storage.nil?
      return if @storage.is_a?(AuthProto::Storage::Interface)

      raise ConfigurationError, "Storage must implement Storage::Interface"
    end

    def validate_http_client
      return if @http_client.nil? # Allow nil for testing
      return if @http_client.respond_to?(:get) && @http_client.respond_to?(:post)

      raise ConfigurationError, "HTTP client must implement get and post methods"
    end
  end
end
