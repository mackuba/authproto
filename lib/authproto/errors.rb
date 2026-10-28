# frozen_string_literal: true

module AuthProto

  # Base class for library errors, except standalone localhost callback errors.
  class Error < StandardError; end

  #
  # Base class for AT Protocol OAuth errors
  #

  class OAuthError < Error

    # OAuth error code associated with the failure.
    # @return [String]
    attr_reader :error_code

    # Creates an OAuth failure with a human-readable message and protocol code.
    #
    # @param message [String] error description
    # @param error_code [String] OAuth error code
    #
    def initialize(message, error_code)
      @error_code = error_code
      # @type-ignore
      super(message)
    end
  end

  #
  # Error raised when client metadata is invalid or cannot be retrieved.
  # This can occur during client metadata fetching, parsing, or validation.
  #
  # @example Handling client metadata errors
  #   begin
  #     client = AuthProto::Client.new(
  #       client_id: "https://myapp.com/metadata.json",
  #       redirect_uri: "https://myapp.com/callback"
  #     )
  #   rescue AuthProto::InvalidClientMetadata => e
  #     puts "Failed to validate client metadata: #{e.message}"
  #   end
  #

  class InvalidClientMetadata < OAuthError

    # Creates a metadata error with the `invalid_client_metadata` code.
    # @param message [String] explanation of the validation or retrieval failure
    def initialize(message)
      super(message, "invalid_client_metadata")
    end
  end

  #
  # Error raised when authorization server metadata is invalid or cannot be retrieved.
  # This includes issues with server metadata fetching, parsing, or validation against
  # the AT Protocol OAuth requirements.
  #
  # @example Handling authorization server errors
  #   begin
  #     server = AuthProto::ServerMetadata::AuthorizationServer.from_issuer("https://auth.example.com")
  #   rescue AuthProto::InvalidAuthorizationServer => e
  #     puts "Failed to validate authorization server: #{e.message}"
  #   end
  #

  class InvalidAuthorizationServer < OAuthError

    # Creates a metadata error with the `invalid_authorization_server` code.
    # @param message [String] explanation of the validation or retrieval failure
    def initialize(message)
      super(message, "invalid_authorization_server")
    end
  end
end
