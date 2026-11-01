# frozen_string_literal: true

module AuthProto

  #
  # Shared helpers for HTTP response hashes returned by the configured transport.
  #

  module HTTPHelpers

    private

    # Looks up a response header without regard to the case of its name.
    #
    # @param response [Hash{Symbol => Object}] HTTP response with an optional `:headers` hash
    # @param name [String] header name, in any case
    # @param strip_parameters [Boolean] return only the trimmed value before the first semicolon
    # @return [String, nil] header value, or `nil` if the header or headers hash is absent
    #
    def response_header(response, name, strip_parameters: false)
      value = (response[:headers] || {}).find { |header, value| header.casecmp?(name) }&.last
      return value unless value && strip_parameters

      value.split(';', 2).first.to_s.strip
    end
  end
end
