# frozen_string_literal: true

require 'authproto'

module OAuth
  class Error < StandardError; end

  class << self
    attr_accessor :metadata, :metadata_path, :client_id, :redirect_uri

    def init
      @metadata_path = ENV.fetch('OAUTH_METADATA_PATH', File.join(__dir__, 'config', 'oauth-client-metadata.json'))
      @keys_path = File.join(__dir__, 'config', 'keys.json')

      unless File.exist?(@metadata_path)
        raise "Copy a metadata template to config/oauth-client-metadata.json before starting the app"
      end

      @metadata = JSON.parse(File.read(@metadata_path))

      @client_id = @metadata.fetch('client_id')
      @redirect_uri = @metadata.fetch('redirect_uris')[0]
      @minisky_options = { client_id: @client_id, redirect_uri: @redirect_uri }

      if @client_id.match?(%r{\Ahttp://localhost(/|$)})
        @oauth_client = AuthProto::Client.for_localhost(redirect_uri: @redirect_uri, scope: @metadata['scope'])
        @minisky_options[:client_id] = @oauth_client.client_id
      else
        signing_key = JSON.parse(File.read(@keys_path))['keys'].first if File.exist?(@keys_path)

        @oauth_client = AuthProto::Client.new(
          client_id: @client_id,
          redirect_uri: @redirect_uri,
          metadata: @metadata,
          signing_key: signing_key
        )

        @minisky_options[:metadata] = @metadata
        @minisky_options[:signing_key] = @signing_key
      end
    end

    def client
      @oauth_client
    end

    def make_minisky(session_id)
      oauth_session = @oauth_client.session_manager.get_session(session_id)
      raise Error, "Session not found" if oauth_session.nil?

      Minisky::OAuthClient.new(oauth_session.pds, **@minisky_options, session_id: session_id)
    end
  end
end
