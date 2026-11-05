# frozen_string_literal: true

require_relative 'authproto/client'
require_relative 'authproto/configuration'
require_relative 'authproto/http_client'
require_relative 'authproto/insecure_http_client'
require_relative 'authproto/localhost_server'
require_relative 'authproto/validated_uri'
require_relative 'authproto/version'

#
# AuthProto is a Ruby implementation of an AT Protocol specific OAuth client.
#
# Supports both public and confidential clients, handles DPoP, nonce management, client and server metadata JSON,
# PAR, PKCE, client assertions for confidential clients, storage of session state, and at rest encryption of stored
# tokens. Includes SQLite, Redis and in-memory storage backends, and an adapter for using the Minisky gem with OAuth
# login support.
#

module AuthProto
end
