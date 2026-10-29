# frozen_string_literal: true

require 'json'
require 'uri'

require_relative '../configuration'
require_relative '../errors'
require_relative '../http_client'
require_relative '../server_metadata'
require_relative '../validated_uri'

module AuthProto
  module ServerMetadata

    #
    # This class represents a Resource Server (PDS) and is responsible for
    # validating and managing its metadata. It ensures that the authorization
    # server URLs provided are valid and compliant with expected standards.
    # The class also includes functionality to fetch and parse metadata from a
    # remote URL, raising specific errors for invalid or malformed metadata.
    #

    class ResourceServer

      # Authorization server origins; validation requires exactly one entry.
      # @return [Array<String>]
      attr_reader :authorization_servers

      # Validates resource server metadata and its single authorization server origin.
      #
      # @param metadata [Hash{String => Object}] discovery document containing `authorization_servers`
      # @raise [InvalidAuthorizationServer] if the list is missing or does not contain one valid origin
      # @raise [URI::InvalidURIError] if the authorization server URI cannot be parsed
      #
      def initialize(metadata)
        @authorization_servers = validate_authorization_servers(metadata["authorization_servers"])
      end

      # Fetches `/.well-known/oauth-protected-resource` using the configured transport.
      # Requires HTTP 200 without redirects, a JSON object served as application/json,
      # and a resource identifier that exactly matches the requested URL.
      # URL scheme restrictions are enforced by the configured transport.
      # The PDS URL must have no userinfo, path prefix, query or fragment.
      #
      # @param url [String] resource server/PDS base URL
      # @return [ResourceServer] validated resource server metadata
      # @raise [InvalidAuthorizationServer] if HTTP transport, JSON parsing or metadata validation fails
      # @raise [HTTPClient::SSRFError] if the transport rejects the initial destination
      # @raise [URI::InvalidURIError] if the PDS or authorization server URL cannot be parsed
      #
      def self.from_url(url)
        validate_source_url(url)

        response = fetch_metadata(url)
        validate_response(response)

        metadata = parse_metadata(response[:body])
        validate_resource(metadata["resource"], url)

        new(metadata)
      end


      private

      def validate_authorization_servers(servers)
        raise InvalidAuthorizationServer, "authorization_servers missing" if servers.nil?
        raise InvalidAuthorizationServer, "authorization_servers is not an array" unless servers.is_a?(Array)
        raise InvalidAuthorizationServer, "must have exactly one authorization server" unless servers.length == 1

        uri = ValidatedURI.new(servers.first)

        valid = (
          uri.scheme == 'https' && (!uri.specified_port || uri.effective_port != 443) &&
          uri.path.empty? && !uri.query && !uri.fragment && !uri.userinfo
        )

        raise InvalidAuthorizationServer, "invalid authorization server URL format for #{servers.first}" unless valid

        servers
      end

      class << self
        private

        def validate_source_url(url)
          uri = ValidatedURI.new(url)

          unless uri.path.empty? && !uri.userinfo && !uri.query && !uri.fragment
            raise InvalidAuthorizationServer,
              "Resource server URL must be an HTTP(S) origin without userinfo, a path prefix, query or fragment"
          end
        rescue URI::InvalidURIError => e
          raise InvalidAuthorizationServer, "Invalid resource server URL: #{e.message}"
        end

        def fetch_metadata(url)
          metadata_url = URI.join(url, "/.well-known/oauth-protected-resource")

          AuthProto.configuration.http_client.get(metadata_url.to_s, follow_redirects: false)
        rescue HTTPClient::HTTPError => e
          raise InvalidAuthorizationServer, "Failed to fetch resource server metadata: #{e.message}"
        end

        def validate_response(response)
          unless response[:status] == 200
            raise InvalidAuthorizationServer, "Resource server metadata must return HTTP 200"
          end

          content_type = response[:headers]["content-type"].to_s.split(";", 2).first.to_s.strip

          unless content_type.casecmp?("application/json")
            raise InvalidAuthorizationServer, "Resource server metadata must use application/json"
          end
        end

        def parse_metadata(body)
          metadata = JSON.parse(body.to_s)

          unless metadata.is_a?(Hash)
            raise InvalidAuthorizationServer, "Resource server metadata must be a JSON object"
          end

          metadata
        rescue JSON::ParserError => e
          raise InvalidAuthorizationServer, "Invalid JSON in resource server metadata: #{e.message}"
        end

        def validate_resource(resource, url)
          unless resource.is_a?(String) && resource == url
            raise InvalidAuthorizationServer, "Resource server metadata resource must match the requested resource URL"
          end
        end
      end
    end
  end
end
