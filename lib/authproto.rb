# frozen_string_literal: true

require_relative 'authproto/client'
require_relative 'authproto/configuration'
require_relative 'authproto/http_client'
require_relative 'authproto/insecure_http_client'
require_relative 'authproto/localhost_server'
require_relative 'authproto/serialization/dpop_key'
require_relative 'authproto/validated_uri'
require_relative 'authproto/version'

#
# AuthProto is a Ruby library implementing the AT Protocol OAuth specification.
# It provides OAuth clients with DPoP, PAR, identity discovery, client metadata
# validation, and storage for sessions and tokens.
#

module AuthProto
end
