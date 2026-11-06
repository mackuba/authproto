# frozen_string_literal: true

require 'strscan'

module AuthProto

  #
  # Shared helpers for HTTP response hashes returned by the configured transport.
  #

  module HTTPHelpers

    private

    def response_status(response)
      status = response[:status]
      status.is_a?(String) && /\A[0-9]+\z/.match?(status) ? status.to_i : status
    end

    # Looks up a response header without regard to the case of its name.
    #
    # @param response [Hash{Symbol => Object}] HTTP response with an optional `:headers` hash
    # @param name [String] header name, in any case
    # @param strip_parameters [Boolean] return only the trimmed value before the first semicolon
    # @return [String, nil] header value, or `nil` if the header or headers hash is absent
    #
    def response_header(response, name, strip_parameters: false)
      value = (response[:headers] || {}).find { |header, value| header.casecmp?(name) }&.last
      value = value.join(', ') if value.is_a?(Array)
      return value unless value && strip_parameters

      value.split(';', 2).first.to_s.strip
    end

    # Finds an authentication scheme in a WWW-Authenticate challenge list.
    # Quoted commas and escapes are preserved while parsing. Scheme and parameter
    # names are case-insensitive; parameter values retain their original case.
    #
    # @param header [String, nil] combined WWW-Authenticate header value
    # @param scheme [String] authentication scheme to select
    # @return [Hash{String => String}, nil] parameters, or `nil` for absent, malformed or multiple matching challenges
    #
    def authentication_challenge(header, scheme:)
      return nil unless header.is_a?(String)

      scanner = StringScanner.new(header)
      matches = []
      scanner.skip(/[ \t]*/)

      loop do
        name = scanner.scan(/[!#$%&'*+\-.^_`|~0-9A-Za-z]+/)
        return nil unless name

        whitespace = scanner.skip(/[ \t]*/)
        params = {}

        unless scanner.eos? || scanner.check(/,/)
          return nil if whitespace.zero?

          # Other schemes can carry token68 credentials rather than parameters.
          unless scanner.scan(/[A-Za-z0-9\-._~+\/]+=*(?=[ \t]*(?:,|\z))/)
            loop do
              parameter = scanner.scan(/[!#$%&'*+\-.^_`|~0-9A-Za-z]+/)&.downcase
              return nil unless parameter && !params.key?(parameter)

              scanner.skip(/[ \t]*/)
              return nil unless scanner.scan(/=/)

              scanner.skip(/[ \t]*/)
              value = scanner.scan(/"(?:\\.|[^"\\])*"/) || scanner.scan(/[!#$%&'*+\-.^_`|~0-9A-Za-z]+/)
              return nil unless value

              params[parameter] = value.start_with?('"') ? value[1...-1].gsub(/\\(.)/, '\\1') : value
              scanner.skip(/[ \t]*/)
              break unless scanner.check(/,[ \t]*[!#$%&'*+\-.^_`|~0-9A-Za-z]+[ \t]*=/)

              scanner.scan(/,[ \t]*/)
            end
          end
        end

        matches << params if name.casecmp?(scheme)
        scanner.skip(/[ \t]*/)
        break if scanner.eos?
        return nil unless scanner.scan(/,[ \t]*/)
      end

      matches.one? ? matches.first : nil
    end
  end
end
