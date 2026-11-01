# frozen_string_literal: true

require 'json'
require 'uri'

require_relative '../configuration'
require_relative '../par'
require_relative 'response'

module AuthProto
  module PAR

    #
    # Client for making Pushed Authorization Requests (PAR) according to RFC 9126.
    # Handles submitting authorization parameters to the PAR endpoint and building
    # the subsequent authorization URL.
    #
    # In AT Protocol OAuth, all authorization requests must first go through PAR.
    # This means instead of sending authorization parameters directly to the
    # authorization endpoint, clients:
    # 1. Submit parameters to the PAR endpoint via POST
    # 2. Receive a request_uri in response
    # 3. Use only the request_uri and client_id in the authorization redirect
    #
    # @example Basic PAR flow
    #   client = AuthProto::PAR::Client.new(
    #     authorization_server: authorization_server,
    #     dpop_client: AuthProto::DPoP::Client.new
    #   )
    #
    #   # Create and submit PAR request using builder pattern
    #   request = AuthProto::PAR::Request.build do |config|
    #     config.client_id = "https://app.example.com/oauth-client-metadata.json"
    #     config.redirect_uri = "https://app.example.com/callback"
    #     config.code_challenge = "abc123..."
    #     config.state = "xyz789..."
    #     config.scope = 'atproto'
    #   end
    #
    #   session = AuthProto::State::Session.new(client_id: client_id, scope: 'atproto')
    #   response = client.submit(request, session: session)
    #
    #   # Build authorization URL using response
    #   auth_url = client.build_authorization_url(
    #     request_uri: response.request_uri,
    #     client_id: request.client_id
    #   )
    #
    # @example With client authentication (confidential clients)
    #   request = AuthProto::PAR::Request.build do |config|
    #     # ... basic parameters ...
    #     config.client_assertion = AuthProto::PAR::ClientAssertion.new(client_id: client_id, signing_key: signing_key)
    #   end
    #
    # All requests use HTTPS and include a fresh DPoP proof from the supplied
    # DPoP client. Nonce challenges are retried once with a new proof. The client
    # validates PAR responses before returning a request URI.
    #

    class Client

      # Authorization server supplying endpoints and the client assertion audience.
      # @return [Metadata::AuthorizationServer]
      attr_reader :authorization_server

      # HTTPS pushed authorization request endpoint.
      # @return [String]
      attr_reader :par_endpoint

      # DPoP client used to sign requests.
      # @return [DPoP::Client]
      attr_reader :dpop_client

      # Creates a PAR transport using the global HTTP client and supplied DPoP client.
      #
      # @param authorization_server [Metadata::AuthorizationServer] discovered authorization server metadata
      # @param dpop_client [DPoP::Client] proof generator and nonce tracker
      #
      def initialize(authorization_server:, dpop_client:)
        @authorization_server = authorization_server
        @par_endpoint = authorization_server.pushed_authorization_request_endpoint
        @dpop_client = dpop_client
        @nonce_manager = dpop_client.nonce_manager
      end

      # Submits a PAR request, handling DPoP nonce requirements
      #
      # @param request [Request] The request to submit
      # @param session [State::Session] session whose key signs PAR and any retries
      # @return [Response] The PAR response
      # @raise [Error] if request fails
      #
      def submit(request, session:)
        raise Error, "Expected a PAR::Request" unless request.is_a?(PAR::Request)

        # Try the initial request
        response = make_request(request, session: session)

        return process_response(response) if response[:status] == 201

        # Handle DPoP nonce requirement
        if requires_nonce?(response)
          nonce = extract_nonce(response)
          store_nonce(nonce)

          # Get stored nonce to verify
          @nonce_manager.get(server_origin)

          # Generate new proof with nonce and retry
          response = make_request(request, session: session)
          return process_response(response) if response[:status] == 201
        end

        handle_error_response(response)
      rescue StandardError => e
        raise Error, "PAR request failed: #{e.message}"
      end

      # Reads a nonce from a transport response hash.
      #
      # @param response [Hash{Symbol => Object}] response containing a `:headers` hash with a `DPoP-Nonce` header
      # @return [String] server-provided nonce
      # @raise [Error] if no supported nonce header is present
      #
      def extract_nonce(response)
        nonce = response[:headers].find { |k, v| k.downcase == 'dpop-nonce' }&.last
        raise Error, "No DPoP nonce provided in response" unless nonce

        nonce
      end

      # Builds the browser URL using the client ID and returned PAR request URI.
      #
      # Retains existing query parameters.
      #
      # @param request_uri [String] request URI from {Response#request_uri}
      # @param client_id [String] OAuth client ID
      # @return [String] browser authorization URL
      # @raise [URI::InvalidURIError] if the authorization endpoint cannot be parsed
      #
      def build_authorization_url(request_uri:, client_id:)
        uri = URI(@authorization_server.authorization_endpoint)

        params = {
          request_uri: request_uri,
          client_id: client_id
        }

        existing_query = uri.query || ''
        params_query = URI.encode_www_form(params).gsub('*', '%2A')   # unescaped '*' may break links in the terminal

        uri.query = existing_query + (existing_query.empty? ? '' : '&') + params_query

        uri.to_s
      end


      private

      def make_request(request, session:)
        # Generate DPoP proof for this request
        proof = dpop_client.generate_proof(
          session: session,
          method: 'POST',
          uri: @par_endpoint,
          nonce: @nonce_manager.get(server_origin)
        )

        # Build headers including DPoP proof
        headers = build_headers(proof)

        # Make the request
        AuthProto.configuration.http_client.post(
          @par_endpoint,
          body: request.to_form(audience: @authorization_server.issuer),
          headers: headers
        )
      end

      def build_headers(dpop_proof)
        {
          "Content-Type" => "application/x-www-form-urlencoded",
          "DPoP" => dpop_proof
        }
      end

      def requires_nonce?(response)
        body = JSON.parse(response[:body])
        body['error'] == DPoP::ERROR_USE_NONCE
      rescue JSON::ParserError
        false
      end

      def store_nonce(nonce)
        @nonce_manager.update(nonce: nonce, server_url: server_origin)
      end

      def server_origin
        uri = URI(@par_endpoint)
        "#{uri.scheme}://#{uri.host}#{":#{uri.port}" if uri.port != uri.default_port}"
      end

      def handle_error_response(response)
        begin
          error_data = JSON.parse(response[:body])
          error_message = error_data['error_description'] || error_data['error'] || "Unknown error"
        rescue JSON::ParserError
          error_message = "Invalid response from server"
        end

        raise Error, "PAR request failed: #{error_message} (status: #{response[:status]})"
      end

      def process_response(response)
        raise Error, "unexpected response status: #{response[:status]}" unless response[:status] == 201

        content_type = (response[:headers] || {}).find { |key, _| key.downcase == 'content-type' }&.last

        unless content_type.to_s.split(';', 2).first.to_s.strip.casecmp?('application/json')
          raise Error, "PAR response must use application/json"
        end

        begin
          data = JSON.parse(response[:body])
          raise Error, "PAR response must be a JSON object" unless data.is_a?(Hash)

          Response.new(
            request_uri: data['request_uri'],
            expires_in: data['expires_in']
          )
        rescue JSON::ParserError => e
          raise Error, "invalid JSON response: #{e.message}"
        rescue StandardError => e
          raise Error, "failed to process response: #{e.message}"
        end
      end
    end
  end
end
