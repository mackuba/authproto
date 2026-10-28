# frozen_string_literal: true

require_relative 'http_client'

module AuthProto

  #
  # Development transport for mixed local HTTP and remote HTTPS requests.
  # Allows private/loopback destinations; HTTPS certificate verification is kept.
  #

  class InsecureHTTPClient < HTTPClient

    # HTTP and HTTPS schemes accepted for development requests.
    # @return [Array<String>]
    ALLOWED_SCHEMES = %w[http https].freeze

    private

    def validate_ip(uri)
      # Deliberately bypass IP restrictions for local development environments.
    end
  end
end
