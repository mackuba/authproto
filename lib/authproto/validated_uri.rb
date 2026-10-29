# frozen_string_literal: true

require 'forwardable'
require 'uri'

module AuthProto

  #
  # An HTTP(S) URI with a required host and preserved source components.
  #
  # Unlike URI::HTTP, port is the explicit port string (or nil when omitted),
  # userinfo preserves an empty component, and path treats "/" as empty.
  # Other readers and string conversion delegate to the parsed URI.
  #

  class ValidatedURI
    extend Forwardable

    attr_reader :port, :userinfo, :path

    def_delegators :@uri, :scheme, :host, :hostname, :query, :fragment,
                   :user, :password, :registry, :opaque, :default_port,
                   :request_uri, :origin, :absolute?, :relative?, :hierarchical?,
                   :to_s, :to_str

    # @param url [String, URI::Generic] URL to parse; URI inputs use their serialized form
    # @raise [URI::InvalidURIError] if the URL is malformed, not HTTP(S), or has no host
    #
    def initialize(url)
      unless url.is_a?(String) || url.is_a?(URI::Generic)
        raise URI::InvalidURIError, "URL must be a string or URI"
      end

      source = url.to_s
      @uri = URI.parse(source)

      unless @uri.is_a?(URI::HTTP) && @uri.host && !@uri.host.empty?
        raise URI::InvalidURIError, "URL must use HTTP or HTTPS and include a host"
      end

      @userinfo, @port = URI.split(source).values_at(1, 3)
      @path = (@uri.path == '/') ? '' : @uri.path
    end

    def specified_port
      port
    end

    def effective_port
      @uri.port
    end

    def to_uri
      @uri
    end
  end
end
