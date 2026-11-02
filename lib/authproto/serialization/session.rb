# frozen_string_literal: true

require 'time'

require_relative '../metadata/authorization_server'
require_relative '../state/session'
require_relative 'base'
require_relative 'token_set'

module AuthProto
  module Serialization

    #
    # Handles serialization of Session objects
    #

    class Session < Base

      # Returns the envelope type used by this serializer.
      # @return [String] `Session`
      def type_identifier
        "Session"
      end

      private

      def validate_object(obj)
        return if obj.is_a?(AuthProto::State::Session)

        raise ValidationError, "Expected Session object, got #{obj.class}"
      end

      def serialize_data(obj)
        data = {
          session_id: obj.session_id,
          client_id: obj.client_id,
          dpop_key: obj.dpop_key.private_jwk,
          scope: obj.scope,
          pkce_verifier: obj.pkce_verifier,
          pkce_challenge: obj.pkce_challenge,
          did: obj.did,
          tokens: serialize_token_set(obj.tokens),
          auth_server: serialize_auth_server(obj.auth_server)
        }

        data[:state_token] = obj.state_token if obj.state_token
        data[:signing_key_id] = obj.signing_key_id if obj.signing_key_id
        data[:signing_key_thumbprint] = obj.signing_key_thumbprint if obj.signing_key_thumbprint
        data[:authorization_expires_at] = obj.authorization_expires_at.utc.iso8601(9) if obj.authorization_expires_at
        data
      end

      def deserialize_data(data)
        unless data['dpop_key'].is_a?(Hash)
          raise ValidationError, "Session is missing its private DPoP key; authorize again"
        end

        session = AuthProto::State::Session.new(
          client_id: data['client_id'],
          dpop_key: AuthProto::DPoP::KeySet.from_jwk(data.fetch('dpop_key')),
          scope: data['scope'],
          did: data['did'],
          signing_key_id: data['signing_key_id'],
          signing_key_thumbprint: data['signing_key_thumbprint'],
          authorization_expires_at: data['authorization_expires_at'] && Time.iso8601(data['authorization_expires_at']),
          auth_server: deserialize_auth_server(data['auth_server'])
        )

        # Set readonly attributes
        session.instance_variable_set(:@session_id, data['session_id'])
        session.instance_variable_set(:@state_token, data['state_token'])
        session.instance_variable_set(:@pkce_verifier, data['pkce_verifier'])
        session.instance_variable_set(:@pkce_challenge, data['pkce_challenge'])

        # Set tokens if present
        session.tokens = deserialize_token_set(data['tokens']) if data['tokens']

        session
      end

      def serialize_token_set(tokens)
        return nil unless tokens

        TokenSet.new.serialize(tokens)
      end

      def deserialize_token_set(data)
        return nil unless data

        TokenSet.new.deserialize(data)
      end

      def serialize_auth_server(server)
        return nil unless server

        server.to_h
      end

      def deserialize_auth_server(data)
        return nil unless data

        AuthProto::Metadata::AuthorizationServer.new(data)
      end
    end
  end
end
