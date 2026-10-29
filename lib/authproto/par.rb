# frozen_string_literal: true

require_relative 'errors'

module AuthProto

  #
  # Handles creation and processing of Pushed Authorization Requests (PAR)
  # according to RFC 9126 and AT Protocol OAuth requirements.
  #
  # PAR is mandatory in AT Protocol OAuth. Before redirecting a user to the
  # authorization endpoint, clients must first submit all authorization parameters
  # via HTTP POST to the PAR endpoint. Only the returned request_uri and client_id
  # are then included in the authorization redirect.
  #
  # @example Basic PAR request
  #   par = AuthProto::PAR::Client.new(
  #     endpoint: "https://auth.example.com/par",
  #     dpop_client: AuthProto::DPoP::Client.new
  #   )
  #
  #   request = AuthProto::PAR::Request.build do |config|
  #     config.client_id = "https://app.example.com/oauth-client-metadata.json"
  #     config.redirect_uri = "https://app.example.com/callback"
  #     config.code_challenge = "abc123..."
  #     config.code_challenge_method = "S256"
  #     config.state = "xyz789..."
  #     config.scope = "atproto"
  #   end
  #
  #   response = par.submit(request)
  #   auth_url = par.authorization_url(
  #     authorize_endpoint: "https://auth.example.com/authorize",
  #     request_uri: response.request_uri,
  #     client_id: request.client_id
  #   )
  #

  module PAR

    # Error raised for PAR-related issues
    class Error < AuthProto::Error; end

    # OAuth JWT bearer client assertion type URN.
    # @return [String]
    CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  end
end
