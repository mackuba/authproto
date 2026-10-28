# frozen_string_literal: true

require 'cgi'

module AuthProto
  module PAR

    #
    # Represents a pushed authorization request
    #

    class Request

      #
      # Configuration for request parameters
      #

      class Configuration

        # OAuth client identifier.
        # @return [String, nil]
        attr_accessor :client_id

        # Registered OAuth callback URI.
        # @return [String, nil]
        attr_accessor :redirect_uri

        # S256 PKCE challenge.
        # @return [String, nil]
        attr_accessor :code_challenge

        # PKCE method; must be `S256`.
        # @return [String, nil]
        attr_accessor :code_challenge_method

        # Random state token to validate the callback.
        # @return [String, nil]
        attr_accessor :state

        # Space-separated scopes including `atproto`.
        # @return [String, nil]
        attr_accessor :scope

        # Account handle to prefill at the authorization server.
        # @return [String, nil]
        attr_accessor :login_hint

        # Optional authorization nonce parameter.
        # @return [String, nil]
        attr_accessor :nonce

        # Optional proof value retained on the request; {Client#submit} generates its own HTTP proof.
        # @return [String, nil]
        attr_accessor :dpop_proof

        # JWT bearer assertion type for confidential clients.
        # @return [String, nil]
        attr_accessor :client_assertion_type

        # Signed client authentication JWT for confidential clients.
        # @return [String, nil]
        attr_accessor :client_assertion
      end

      # OAuth response type; always `code`.
      # @return [String]
      attr_reader :response_type

      # OAuth client identifier.
      # @return [String]
      attr_reader :client_id

      # Registered OAuth callback URI.
      # @return [String]
      attr_reader :redirect_uri

      # S256 PKCE challenge.
      # @return [String]
      attr_reader :code_challenge

      # PKCE method; must be `S256`.
      # @return [String]
      attr_reader :code_challenge_method

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
        # Required parameters
        @response_type = "code" # Always "code" for AT Protocol OAuth
        @client_id = config.client_id
        @redirect_uri = config.redirect_uri
        @code_challenge = config.code_challenge
        @code_challenge_method = config.code_challenge_method
        @state = config.state
        @scope = config.scope

        # Optional parameters
        @login_hint = config.login_hint
        @nonce = config.nonce
        @dpop_proof = config.dpop_proof

        # Client authentication
        @client_assertion_type = config.client_assertion_type
        @client_assertion = config.client_assertion

        validate_request
      end

      # Converts request to form-encoded parameters
      # @return [String] Form-encoded request body
      def to_form
        encode_params(build_params)
      end

      private

      def build_params
        params = {
          "response_type" => response_type,
          "client_id" => client_id,
          "redirect_uri" => redirect_uri,
          "code_challenge" => code_challenge,
          "code_challenge_method" => code_challenge_method,
          "state" => state,
          "scope" => scope
        }

        add_optional_params(params)
        add_client_auth_params(params)
        params
      end

      def add_optional_params(params)
        params["login_hint"] = login_hint if login_hint
        params["nonce"] = nonce if nonce
      end

      def add_client_auth_params(params)
        return unless client_assertion

        params["client_assertion_type"] = CLIENT_ASSERTION_TYPE
        params["client_assertion"] = client_assertion
      end

      def validate_request
        validate_required_params
        validate_response_type
        validate_code_challenge_method
        validate_scope
        validate_client_auth
      end

      def validate_required_params
        %i[client_id redirect_uri code_challenge code_challenge_method state scope].each do |param|
          value = send(param)
          raise Error, "#{param} is required" if value.nil? || value.empty?
        end
      end

      def validate_response_type
        return if response_type == "code"

        raise Error, "response_type must be 'code'"
      end

      def validate_code_challenge_method
        return if code_challenge_method == "S256"

        raise Error, "code_challenge_method must be 'S256'"
      end

      def validate_scope
        scopes = scope.split
        raise Error, "atproto scope is required" unless scopes.include?("atproto")
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

      def encode_params(params)
        params.map { |k, v| "#{CGI.escape(k)}=#{CGI.escape(v.to_s)}" }.join("&")
      end
    end
  end
end
