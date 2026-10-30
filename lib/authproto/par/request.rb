# frozen_string_literal: true

require 'uri'

require_relative '../par'

module AuthProto
  module PAR

    #
    # Represents a pushed authorization request.
    #

    class Request

      #
      # Shared set of fields between {Request} (a read-only, validated request) and {Configuration} (a draft request
      # with writable fields configured in the block passed to {Request.build}).
      #

      module Fields

        # OAuth client identifier.
        # @return [String]
        attr_reader :client_id

        # Registered OAuth callback URI.
        # @return [String]
        attr_reader :redirect_uri

        # S256 PKCE challenge.
        # @return [String]
        attr_reader :code_challenge

        # Random state token to validate the callback.
        # @return [String]
        attr_reader :state

        # Space-separated scopes including `atproto`.
        # @return [String]
        attr_reader :scope

        # Account handle to prefill at the authorization server.
        # @return [String, nil]
        attr_reader :login_hint

        # Optional authorization nonce parameter.
        # @return [String, nil]
        attr_reader :nonce

        # Optional proof value retained on the request; {Client#submit} generates its own HTTP proof.
        # @return [String, nil]
        attr_reader :dpop_proof

        # JWT bearer assertion type for confidential clients.
        # @return [String, nil]
        attr_reader :client_assertion_type

        # Signed client authentication JWT for confidential clients.
        # @return [String, nil]
        attr_reader :client_assertion
      end

      #
      # A draft PAR request with writable fields, configured inside the block passed to {Request.build}).
      #

      class Configuration
        include Fields

        send(:attr_writer, *Fields.instance_methods(false))
      end

      include Fields


      # Builds a validated PAR request by yielding a mutable parameter configuration.
      #
      # @yield [config] block that sets the request parameters
      # @yieldparam config [Configuration] mutable request settings
      # @yieldreturn [Object] ignored
      # @return [Request] validated pushed authorization request
      # @raise [Error] if required parameters, PKCE, scope or client authentication are invalid
      #
      def self.build
        config = Configuration.new
        yield(config)
        new(config)
      end

      # Copies and validates a PAR parameter configuration.
      #
      # @param config [Configuration] populated request settings
      # @raise [Error] if required values are missing or authentication/PKCE/scope values are invalid
      #
      def initialize(config)
        Fields.instance_methods(false).each do |field|
          self.instance_variable_set("@#{field}", config.send(field))
        end

        validate_request
      end

      # Converts request to form-encoded parameters
      # @return [String] Form-encoded request body
      #
      def to_form
        URI.encode_www_form(build_params)
      end


      private

      def build_params
        params = {
          "response_type" => 'code',
          "client_id" => client_id,
          "redirect_uri" => redirect_uri,
          "code_challenge" => code_challenge,
          "code_challenge_method" => PKCE::CHALLENGE_METHOD_S256,
          "state" => state,
          "scope" => scope
        }

        params['login_hint'] = login_hint if login_hint
        params['nonce'] = nonce if nonce

        if client_assertion
          params['client_assertion_type'] = CLIENT_ASSERTION_TYPE
          params['client_assertion'] = client_assertion
        end

        params
      end

      def validate_request
        validate_required_params
        validate_client_auth

        raise Error, "atproto scope is required" unless scope.split.include?('atproto')
      end

      def validate_required_params
        %i[client_id redirect_uri code_challenge state scope].each do |param|
          value = send(param)
          raise Error, "#{param} is required" if value.nil? || value.empty?
        end
      end

      def validate_client_auth
        # If either auth parameter is present, both must be present and valid
        has_assertion = !client_assertion.nil?
        has_type = !client_assertion_type.nil?

        return unless has_assertion || has_type

        unless client_assertion_type == CLIENT_ASSERTION_TYPE
          raise Error, "client_assertion_type must be #{CLIENT_ASSERTION_TYPE}"
        end

        raise Error, "client_assertion required with client_assertion_type" if client_assertion.nil?
        raise Error, "client_assertion_type required with client_assertion" if client_assertion_type.nil?
      end
    end
  end
end
