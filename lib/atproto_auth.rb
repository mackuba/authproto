# frozen_string_literal: true

require 'jose'
require 'jwt'

require 'atproto_auth/version'

require 'atproto_auth/errors'
require 'atproto_auth/configuration'
require 'atproto_auth/encryption'
require 'atproto_auth/client_metadata'
require 'atproto_auth/http_client'
require 'atproto_auth/insecure_http_client'
require 'atproto_auth/localhost_server'
require 'atproto_auth/pkce'

require 'atproto_auth/storage/interface'
require 'atproto_auth/storage/key_builder'
require 'atproto_auth/storage/memory'

AuthProto::Storage.autoload :Redis, 'atproto_auth/storage/redis'
AuthProto::Storage.autoload :SQLite, 'atproto_auth/storage/sqlite'

require 'atproto_auth/server_metadata'
require 'atproto_auth/server_metadata/origin_url'
require 'atproto_auth/server_metadata/authorization_server'
require 'atproto_auth/server_metadata/resource_server'

require 'atproto_auth/dpop/key_manager'
require 'atproto_auth/dpop/proof_generator'
require 'atproto_auth/dpop/nonce_manager'
require 'atproto_auth/dpop/client'

require 'atproto_auth/state'
require 'atproto_auth/state/token_set'
require 'atproto_auth/state/session'
require 'atproto_auth/state/session_manager'

require 'atproto_auth/par'
require 'atproto_auth/par/client_assertion'
require 'atproto_auth/par/request'
require 'atproto_auth/par/response'
require 'atproto_auth/par/client'

require 'atproto_auth/serialization/base'
require 'atproto_auth/serialization/dpop_key'
require 'atproto_auth/serialization/session'
require 'atproto_auth/serialization/stored_nonce'
require 'atproto_auth/serialization/token_set'

require 'atproto_auth/token/refresh'

require 'atproto_auth/client'

#
# AuthProto is a Ruby library implementing the AT Protocol OAuth specification.
# It provides OAuth clients with DPoP, PAR, identity discovery, client metadata
# validation, and storage for sessions and tokens.
#

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
    # @raise [ConfigurationError] if the storage or HTTP client is invalid
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
end
