# frozen_string_literal: true

require 'authproto'

module OAuth
  class Error < StandardError; end

  class << self
    attr_accessor :metadata, :metadata_path

    def init
      @metadata_path = ENV.fetch('OAUTH_METADATA_PATH', File.join(__dir__, 'config', 'oauth-client-metadata.json'))
      @keys_path = File.join(__dir__, 'config', 'keys.json')

      unless File.exist?(@metadata_path)
        raise "Copy a metadata template to config/oauth-client-metadata.json before starting the app"
      end

      @metadata = JSON.parse(File.read(@metadata_path))

      client_id = @metadata.fetch('client_id')
      redirect_uri = @metadata.fetch('redirect_uris')[0]

      if client_id.match?(%r{\Ahttp://localhost(/|$)})
        @localhost = true
        @oauth_client = AuthProto::Client.for_localhost(redirect_uri: redirect_uri, scope: @metadata['scope'])
      else
        @signing_key = JSON.parse(File.read(@keys_path))['keys'].first if File.exist?(@keys_path)

        @oauth_client = AuthProto::Client.new(
          client_id: client_id,
          redirect_uri: redirect_uri,
          metadata: @metadata,
          signing_key: @signing_key
        )
      end
    end

    def client
      @oauth_client
    end

    def make_minisky(session_id)
      if @localhost
        Minisky::OAuthClient.for_localhost(
          redirect_uri: @metadata['redirect_uris'][0],
          scope: @metadata['scope'],
          session_id: session_id
        )
      else
        Minisky::OAuthClient.new(
          client_id: @metadata['client_id'],
          redirect_uri: @metadata['redirect_uris'][0],
          metadata: @metadata,
          signing_key: @signing_key,
          session_id: session_id
        )
      end
    end
  end
end
