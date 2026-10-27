# frozen_string_literal: true

require 'ipaddr'
require 'net/http'
require 'openssl'
require 'resolv'
require 'uri'

module AuthProto

  #
  # A secure HTTP client for making OAuth-related requests.
  # Implements protections against SSRF attacks and enforces security headers.
  #

  class HTTPClient

    # IPv4/IPv6 destinations rejected by the secure transport.
    # @return [Array<IPAddr>]
    FORBIDDEN_IP_RANGES = [
      IPAddr.new("0.0.0.0/8"),      # Current network
      IPAddr.new("10.0.0.0/8"),     # Private network
      IPAddr.new("127.0.0.0/8"),    # Loopback
      IPAddr.new("169.254.0.0/16"), # Link-local
      IPAddr.new("172.16.0.0/12"),  # Private network
      IPAddr.new("192.168.0.0/16"), # Private network
      IPAddr.new("::/128"),         # Unspecified IPv6 address
      IPAddr.new("::1/128"),        # IPv6 loopback
      IPAddr.new("fc00::/7"),       # Unique local address
      IPAddr.new("fe80::/10")       # Link-local address
    ].freeze

    # URL schemes accepted by the secure transport; HTTPS only.
    # @return [Array<String>]
    ALLOWED_SCHEMES = ["https"].freeze

    # Default open/read timeout in seconds.
    # @return [Integer]
    DEFAULT_TIMEOUT = 10 # seconds

    # Maximum redirects followed for a single request.
    # @return [Integer]
    MAX_REDIRECTS = 5

    # Maximum accepted response body size in bytes.
    # @return [Integer]
    MAX_RESPONSE_SIZE = 10 * 1024 * 1024 # 10MB

    # Error raised when a request is blocked due to SSRF protection
    class SSRFError < Error; end

    #
    # Error raised when an HTTP request fails
    #

    class HTTPError < Error

      # Response associated with the failure, when retained by the transport.
      # @return [Net::HTTPResponse, nil]
      attr_reader :response

      # Creates an HTTP transport error with an optional response.
      #
      # @param message [String] failure description
      # @param response [Net::HTTPResponse, nil] response associated with the error
      #
      def initialize(message, response)
        @response = response
        super(message)
      end
    end

    # Value object for redirect request context.
    #
    # Fields are `original_uri` (URI::HTTP), `method` (Symbol), `response`
    # (Net::HTTPResponse), `headers` (a string-keyed header hash), `redirect_count`
    # (Integer), and `body` (String, Hash or nil). Inherits construction and immutable
    # member access from `Data`.
    #
    # @see Data
    #
    RedirectHandlerOptions = Data.define(:original_uri, :method, :response, :headers, :redirect_count, :body)

    # Creates an HTTP transport with timeouts and certificate verification settings.
    #
    # @param timeout [Numeric] open and read timeout, each in seconds
    # @param verify_ssl [Boolean] whether HTTPS peer certificates must be verified
    #
    def initialize(timeout: DEFAULT_TIMEOUT, verify_ssl: true)
      @timeout = timeout
      @verify_ssl = verify_ssl
    end

    # Sends an HTTP GET request with destination validation and redirect handling.
    #
    # Uses HTTPS and rejects private/loopback destinations by default. Subclasses may
    # relax these rules. Follows at most {MAX_REDIRECTS} redirects and checks size
    # against {MAX_RESPONSE_SIZE} using `Content-Length`, or body bytes when absent.
    # Non-2xx status codes are returned for the caller to interpret; they do not
    # themselves raise an exception.
    #
    # @param url [String] absolute HTTPS request URL without a fragment
    # @param headers [Hash{String => String}] additional request headers; can override the default `Cache-Control` value
    # @return [Hash{Symbol => Integer, Hash{String => String}, String, nil}] `:status` (Integer), lowercase `:headers` (Hash), and `:body` (String or nil)
    # @raise [SSRFError] if initial scheme, host, fragment or resolved address is rejected
    # @raise [HTTPError] if transport, TLS, redirect validation or response size checks fail
    # @raise [URI::InvalidURIError] if the initial URL cannot be parsed
    #
    def get(url, headers = {})
      uri = validate_uri(url)
      validate_ip(uri)

      response = make_request(uri, headers)
      validate_response(response)

      {
        status: response.code.to_i,
        headers: response.each_header.to_h,
        body: response.body
      }
    end

    # Sends an HTTP POST request with destination validation and redirect handling.
    #
    # Uses HTTPS and rejects private/loopback destinations by default. Subclasses may
    # relax these rules. Follows at most {MAX_REDIRECTS} redirects and checks size
    # against {MAX_RESPONSE_SIZE} using `Content-Length`, or body bytes when absent.
    # Non-2xx status codes are returned for the caller to interpret; they do not
    # themselves raise an exception.
    #
    # @param url [String] absolute HTTPS request URL without a fragment
    # @param body [String, Hash, nil] raw bytes, form fields encoded with `URI.encode_www_form`, or no body
    # @param headers [Hash{String => String}] additional request headers; can override the default `Cache-Control` value
    # @return [Hash{Symbol => Integer, Hash{String => String}, String, nil}] `:status` (Integer), lowercase `:headers` (Hash), and `:body` (String or nil)
    # @raise [SSRFError] if initial scheme, host, fragment or resolved address is rejected
    # @raise [HTTPError] if transport, TLS, redirect validation or response size checks fail
    # @raise [URI::InvalidURIError] if the initial URL cannot be parsed
    #
    def post(url, body: nil, headers: {})
      uri = validate_uri(url)
      validate_ip(uri)

      response = make_post_request(uri, body, headers)
      validate_response(response)

      {
        status: response.code.to_i,
        headers: response.each_header.to_h,
        body: response.body
      }
    end


    private

    def validate_uri(url)
      uri = URI(url)
      unless self.class::ALLOWED_SCHEMES.include?(uri.scheme)
        raise SSRFError, "URL scheme must be one of: #{self.class::ALLOWED_SCHEMES.join(", ")}"
      end

      # Extract and validate host before any network activity
      host = uri.host.to_s.strip
      raise SSRFError, "URL must include host" if host.empty?
      raise SSRFError, "URL must not include fragment" if uri.fragment

      uri
    end

    def validate_ip(uri)
      # URI#hostname removes brackets from IPv6 literals.
      begin
        parsed_ip = IPAddr.new(uri.hostname)
      rescue IPAddr::InvalidAddressError
        parsed_ip = nil
      end

      if parsed_ip
        if forbidden_ip?(parsed_ip)
          raise SSRFError, "Request to forbidden IP address"
        else
          return
        end
      end

      # Also check resolved IPs for hostnames
      begin
        ips = Resolv::DNS.new.getaddresses(uri.hostname)
        raise SSRFError, "Could not resolve hostname" if ips.empty?

        ips.each do |x|
          ip_addr = IPAddr.new(x.to_s)
          raise SSRFError, "Request to forbidden IP address" if forbidden_ip?(ip_addr)
        rescue IPAddr::InvalidAddressError
          next
        end
      rescue Resolv::ResolvError
        raise SSRFError, "Could not resolve hostname"
      end
    end

    def forbidden_ip?(ip)
      ip = ip.native if ip.ipv4_mapped?
      FORBIDDEN_IP_RANGES.any? { |range| range.include?(ip) }
    end

    def make_request(uri, headers = {}, redirect_count = 0)
      http = Net::HTTP.new(uri.hostname, uri.port)
      configure_http_client(http, ssl: uri.scheme == "https")

      request = Net::HTTP::Get.new(uri.request_uri)
      add_security_headers(request, headers)
      response = http.request(request)
      handle_redirect(
        original_uri: uri,
        response: response,
        headers: headers,
        redirect_count: redirect_count
      )
    rescue Net::OpenTimeout, Net::ReadTimeout => e
      raise HTTPError.new("Request timeout: #{e.message}", nil)
    rescue StandardError => e
      raise HTTPError.new("Request failed: #{e.message}", nil)
    end

    def make_post_request(uri, body, headers = {}, redirect_count = 0)
      http = Net::HTTP.new(uri.hostname, uri.port)
      configure_http_client(http, ssl: uri.scheme == "https")

      request = Net::HTTP::Post.new(uri.request_uri)
      add_security_headers(request, headers)
      request.body = body.is_a?(Hash) ? URI.encode_www_form(body) : body if body

      response = http.request(request)
      handle_redirect(
        original_uri: uri,
        body: body,
        method: :post,
        response: response,
        headers: headers,
        redirect_count: redirect_count
      )
    rescue Net::OpenTimeout, Net::ReadTimeout => e
      raise HTTPError.new("Request timeout: #{e.message}", nil)
    rescue StandardError => e
      raise HTTPError.new("Request failed: #{e.message}", nil)
    end

    def configure_http_client(http, ssl: true)
      http.use_ssl = ssl
      http.verify_mode = @verify_ssl ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
      http.read_timeout = @timeout
      http.open_timeout = @timeout
    end

    def add_security_headers(request, headers)
      # Prevent caching of sensitive data
      request["Cache-Control"] = "no-store"

      # Add user-provided headers
      headers.each { |k, v| request[k] = v }
    end

    # Handle HTTP redirects
    # kwargs can include:
    # - original_uri: URI of the original request
    # - method: HTTP method of the original request (:get or :post)
    # - response: Net::HTTPResponse object
    # - headers: Hash of headers from the original request
    # - redirect_count: Number of redirects so far
    # - body: Request body for POST requests
    #
    def handle_redirect(**kwargs)
      response = kwargs[:response]
      redirect_count = kwargs[:redirect_count]

      return response unless response.is_a?(Net::HTTPRedirection)
      raise HTTPError.new("Too many redirects", response) if redirect_count >= MAX_REDIRECTS

      location = URI(response["location"])
      location = kwargs[:original_uri] + location if location.relative?

      validate_uri(location.to_s)
      validate_ip(location)

      # Increment redirect count for the next request
      redirect_count += 1

      # Recursive call to handle the next redirect
      if kwargs[:method] == :post
        make_post_request(location, kwargs[:body], kwargs[:headers], redirect_count)
      else
        make_request(location, kwargs[:headers], redirect_count)
      end
    end

    def validate_response(response)
      # check_success_status(response)
      check_content_length(response)
    end

    def check_success_status(response)
      return if response.is_a?(Net::HTTPSuccess)

      raise HTTPError.new("HTTP request failed: #{response.code} #{response.message}", response)
    end

    def check_content_length(response)
      content_length = response["content-length"]&.to_i || response.body&.bytesize || 0
      return unless content_length > MAX_RESPONSE_SIZE

      raise HTTPError.new("Response too large: #{content_length} bytes", response)
    end
  end
end
