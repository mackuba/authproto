# frozen_string_literal: true

require 'jose'
require 'jwt'

require 'authproto/version'

require 'authproto/errors'
require 'authproto/configuration'
require 'authproto/encryption'
require 'authproto/client_metadata'
require 'authproto/http_client'
require 'authproto/insecure_http_client'
require 'authproto/localhost_server'
require 'authproto/pkce'

require 'authproto/storage/interface'
require 'authproto/storage/key_builder'
require 'authproto/storage/memory'

AuthProto::Storage.autoload :Redis, 'authproto/storage/redis'
AuthProto::Storage.autoload :SQLite, 'authproto/storage/sqlite'

require 'authproto/server_metadata'
require 'authproto/server_metadata/origin_url'
require 'authproto/server_metadata/authorization_server'
require 'authproto/server_metadata/resource_server'

require 'authproto/dpop/key_manager'
require 'authproto/dpop/proof_generator'
require 'authproto/dpop/nonce_manager'
require 'authproto/dpop/client'

require 'authproto/state'
require 'authproto/state/token_set'
require 'authproto/state/session'
require 'authproto/state/session_manager'

require 'authproto/par'
require 'authproto/par/client_assertion'
require 'authproto/par/request'
require 'authproto/par/response'
require 'authproto/par/client'

require 'authproto/serialization/base'
require 'authproto/serialization/dpop_key'
require 'authproto/serialization/session'
require 'authproto/serialization/stored_nonce'
require 'authproto/serialization/token_set'

require 'authproto/token/refresh'

require 'authproto/client'

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
