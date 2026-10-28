# frozen_string_literal: true

module AuthProto
  module Storage

    #
    # Utility for building storage keys with correct format
    #

    class KeyBuilder

      # Separator between storage key components.
      # @return [String]
      NAMESPACE_SEPARATOR = ":"

      # Root namespace for every generated storage key.
      # @return [String]
      NAMESPACE_PREFIX = "atproto"

      class << self

        # Builds a namespaced storage key for a session.
        #
        # @param id [String] session ID
        # @return [String] colon-separated key beginning with `atproto:`
        #
        def session_key(id)
          build_key("session", id)
        end

        # Builds a namespaced storage key for a state-token lookup.
        #
        # @param token [String] OAuth state token
        # @return [String] colon-separated key beginning with `atproto:`
        #
        def state_key(token)
          build_key("state", token)
        end

        # Builds a namespaced storage key for a DPoP nonce.
        #
        # @param server_url [String] server origin URL
        # @return [String] colon-separated key beginning with `atproto:`
        #
        def nonce_key(server_url)
          build_key("nonce", server_url)
        end

        # Builds a namespaced storage key for a DPoP key.
        #
        # @param client_id [String] OAuth client ID
        # @return [String] colon-separated key beginning with `atproto:`
        #
        def dpop_key(client_id)
          build_key("dpop", client_id)
        end

        # Builds a namespaced storage key for a lock.
        #
        # @param namespace [String] lock namespace, such as `session`
        # @param id [String] resource identifier
        # @return [String] colon-separated key beginning with `atproto:`
        #
        def lock_key(namespace, id)
          build_key("lock", namespace, id)
        end

        private

        def build_key(*parts)
          [NAMESPACE_PREFIX, *parts].join(NAMESPACE_SEPARATOR)
        end
      end
    end
  end
end
