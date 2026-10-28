# frozen_string_literal: true

require 'uri'

module AuthProto
  module ServerMetadata

    #
    # The `OriginURL` class provides validation logic for URLs that must conform
    # to the AT Protocol OAuth "simple origin URL" requirements. These requirements
    # are common between Resource and Authorization Servers and ensure that the URL
    # is valid and secure for use in the protocol. This class validates that the URL:
    # - Uses the HTTPS scheme.
    # - Points to the root path (either an empty path or "/").
    # - Does not include a query string or fragment.
    # - Does not include user or password credentials.
    # - May include a non-default port but disallows the default HTTPS port (443).
    #
    # This model centralizes the URL validation logic to promote reusability and
    # consistency between different server classes.
    #

    class OriginURL

      # Original URL string supplied by the caller.
      # @return [String]
      attr_reader :url

      # Parsed URI used for origin validation.
      # @return [URI::Generic]
      attr_reader :uri

      # Parses a candidate server origin; call {#valid?} to check origin restrictions.
      #
      # @param url [String] origin URL to parse
      # @raise [URI::InvalidURIError] if the input cannot be parsed as a URI
      #
      def initialize(url)
        @url = url
        @uri = URI(url)
      end

      # Determines if a URL conforms to AT Protocol OAuth "simple origin URL" requirements
      # @return [Boolean] true if the URL is a valid origin URL
      def valid?
        https_scheme? &&
          root_path? &&
          !uri.query &&
          !uri.fragment &&
          !uri.userinfo &&
          (!explicit_port? || uri.port != 443)
      end

      private

      def https_scheme?
        uri.scheme == "https"
      end

      def root_path?
        uri.path.empty? || uri.path == "/"
      end

      def explicit_port?
        url.match?(/:\d+/)
      end
    end
  end
end
