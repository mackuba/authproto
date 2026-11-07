# frozen_string_literal: true

require 'json'
require 'securerandom'
require 'time'
require 'uri'

require 'authproto'
require 'dotenv/load'
require 'faraday'
require 'sinatra/base'
require 'sinatra/reloader'


class ExampleApp < Sinatra::Base
  configure :development do
    register Sinatra::Reloader
  end

  configure do
    # Configure AuthProto settings
    AuthProto.configure do |config|
      config.http_client = AuthProto::HTTPClient.new(timeout: 10)

      storage = ENV.fetch("STORAGE_BACKEND", 'memory')

      case storage
      when 'memory'
        config.storage = AuthProto::Storage::Memory.new
      when 'sqlite'
        config.storage = AuthProto::Storage::SQLite.new(
          path: ENV.fetch("SQLITE_PATH", File.join(__dir__, 'db', 'authproto.sqlite3'))
        )
      when 'redis'
        config.storage = AuthProto::Storage::Redis.new(
          redis_client: Redis.new(url: ENV.fetch("REDIS_URL"))
        )
      else
        raise "STORAGE_BACKEND must be memory, sqlite, or redis"
      end
    end

    # Load client metadata
    metadata_path = File.join(__dir__, 'config', 'oauth-client-metadata.json')
    raise "Missing metadata JSON file at config/oauth-client-metadata.json" unless File.exist?(metadata_path)

    metadata = JSON.parse(File.read(metadata_path))
    client_id = metadata['client_id']
    redirect_uri = metadata['redirect_uris'][0]

    keys_path = File.join(__dir__, 'config', 'keys.json')

    # Load private signing key for client assertions, if found
    if File.exist?(keys_path)
      signing_key = JSON.parse(File.read(keys_path))['keys'].first
    end

    if AuthProto::Client.localhost_app?(client_id)
      # For localhost apps, redirect_uri & scope are appended as query params to the client_id URI
      # Use this helper which does that for you:
      oauth_client = AuthProto::Client.for_localhost(redirect_uri: redirect_uri, scope: metadata['scope'])

      if signing_key
        warn "-" * 100
        warn "Running the app on localhost as a public client - confidential clients require a production server."
        warn "-" * 100
      end
    else
      oauth_client = AuthProto::Client.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        metadata: metadata,
        signing_key: signing_key
      )

      # Apps on a live server can be public or confidential clients
      if !signing_key
        warn "-" * 100
        warn "Missing config/keys.json - running the app as a public client."
        warn "-" * 100
      end
    end

    # Store the OAuth client in the global settings
    set :oauth_client, oauth_client
    set :metadata_path, metadata_path

    set :host_authorization, {
      permitted_hosts: ["localhost", ENV.fetch("PERMITTED_DOMAIN", nil)].compact
    }

    session_secret = ENV.fetch("SESSION_SECRET") { SecureRandom.hex(32) }
    raise "SESSION_SECRET must be at least 64 characters long (got: #{session_secret})" if session_secret.length < 64

    use Rack::Session::Cookie,
        key: "atproto.session",
        expire_after: 86_400, # 1 day in seconds
        secret: session_secret,
        secure: ENV.fetch("RACK_ENV", "development") == "production",  # Only send over HTTPS
        httponly: true,     # Not accessible via JavaScript
        same_site: :lax     # CSRF protection
  end

  helpers do
    def load_session
      session_id = session[:oauth_session_id]
      return nil unless session_id

      begin
        return nil unless settings.oauth_client.authorized?(session_id)
        session_id
      rescue AuthProto::Client::SessionError
        # Clear invalid session
        session.delete(:oauth_session_id)
        nil
      end
    end

    def log_error(e)
      if settings.development?
        puts e
        puts e.backtrace.take_while { |l| !l.include?('/lib/sinatra/base') }
      end
    end

    def html_escape(text)
      Rack::Utils.escape_html(text)
    end
  end

  # The landing / login page
  get "/" do
    redirect "/authorized" if load_session

    erb :index
  end

  # Client metadata served on a standard endpoint (only needed on the live site)
  get "/oauth-client-metadata.json" do
    content_type :json

    File.read(settings.metadata_path)
  end

  # Starts the OAuth flow and redirects the user to the PDS's OAuth authorization page
  post "/authenticate" do
    handle = params[:handle]

    begin
      auth = settings.oauth_client.authorize(
        handle: handle,
        scope: "atproto repo:app.bsky.feed.post"
      )

      session_id, authorization_url = auth.values_at(:session_id, :url)

      # Remember the ID of the created OAuth session in the browser session.
      #
      # We need to extract it later when receiving the callback completing the authorization, in order to verify
      # that the authorization was started in the same browser session (and that we aren't logging in the user to
      # someone else's browser session).

      session[:pending_oauth_session_id] = session_id

      # This is an authorization URL on the user's PDS, redirect them there:
      redirect authorization_url
    rescue StandardError => e
      log_error(e)
      session[:error] = "Authorization failed: #{e.message}"
      redirect "/"
    end
  end

  # OAuth callback handler to which the user gets redirected back, which completes the authorization flow
  get "/callback" do
    # Handle possible errors (e.g. user has rejected authorization)
    # You can also pass it as is to `oauth_client.handle_callback` and get a `CallbackError`
    if params[:error]
      message = params[:error]
      message += ": " + params[:error_description] if params[:error_description]
      session[:error] = "Authorization failed: #{message}"
      redirect "/"
    end

    # Extract the session ID previously stored in this browser session and pass it to oauth_client for verification.
    pending_session_id = session[:pending_oauth_session_id]

    result = settings.oauth_client.handle_callback(
      params,
      expected_session_id: pending_session_id
    )

    session.delete(:pending_oauth_session_id)
    session[:oauth_session_id] = result[:session_id]

    redirect "/authorized"
  rescue StandardError => e
    log_error(e)
    session[:error] = "Authorization failed: #{e.message}"
    redirect "/"
  end

  # Home page for a logged in user. Makes a sample request to test authorization headers API.
  get "/authorized" do
    session_id = load_session
    redirect "/" if session_id.nil?

    # Get current session info
    oauth_session = settings.oauth_client.get_tokens(session_id)

    # Check if token needs refresh
    begin
      if oauth_session[:expires_in] < 30
        oauth_session = settings.oauth_client.refresh_token(session_id)
      end
    rescue StandardError => e
      log_error(e)
      session[:error] = "Token refresh failed: #{e.message}"
      halt erb(:index)
    end

    # Make test API call to com.atproto.server.checkAccountStatus using Faraday
    begin
      pds = oauth_session[:pds]
      endpoint = "/xrpc/com.atproto.server.checkAccountStatus"
      url = URI.join(pds, endpoint)

      connection = Faraday.new(url: pds) do |f|
        f.request :json
      end

      # This wrapper repeats the request if needed with updated DPoP nonce
      response = settings.oauth_client.with_nonce_handling(session_id, url) do
        # Create authentication headers for this request
        headers = settings.oauth_client.auth_headers(
          session_id: session_id,
          method: 'GET',
          url: url
        )

        # Make authenticated request
        res = connection.get(endpoint) do |req|
          req.headers.merge!(headers)
        end

        # Convert the Faraday response to expected format
        { status: res.status, body: res.body, headers: res.headers }
      end

      if response[:status] == 200
        @api_result = JSON.parse(response[:body])
        @session = oauth_session
      else
        session[:error] = "API call failed: HTTP #{response[:status]}: #{response[:body]}"
      end

      erb :authorized
    rescue StandardError => e
      log_error(e)
      session[:error] = "API call failed: #{e.message}"
      erb :index
    end
  end

  # Make a test post on Bluesky
  post "/posts" do
    session_id = load_session
    redirect "/" if session_id.nil?

    # Get current session info
    oauth_session = settings.oauth_client.get_tokens(session_id)

    text = params[:text].to_s

    if text.strip.empty?
      session[:error] = "Post text cannot be empty"
      redirect "/authorized"
    end

    if text.length > 300 || text.bytesize > 3_000
      session[:error] = "Post text must be at most 300 characters and 3,000 bytes"
      redirect "/authorized"
    end

    pds = oauth_session[:pds]
    endpoint = "/xrpc/com.atproto.repo.createRecord"
    url = URI.join(pds, endpoint)

    record = {
      repo: oauth_session[:did],
      collection: "app.bsky.feed.post",
      record: {
        text: text,
        langs: ["en"],
        createdAt: Time.now.utc.iso8601(3)
      }
    }

    connection = Faraday.new(url: pds) do |f|
      f.request :json
    end

    # This wrapper repeats the request if needed with updated DPoP nonce
    response = settings.oauth_client.with_nonce_handling(session_id, url) do
      # Create authentication headers for this request
      headers = settings.oauth_client.auth_headers(
        session_id: session_id,
        method: 'POST',
        url: url
      )

      # Make authenticated request
      res = connection.post(endpoint) do |req|
        req.headers.merge!(headers)
        req.body = record
      end

      # Convert the Faraday response to expected format
      { status: res.status, body: res.body, headers: res.headers }
    end

    unless response[:status] == 200
      session[:error] = "Error #{response[:status]}: #{response[:body]}"
      redirect "/authorized"
    end

    session[:notice] = "Post published successfully"
    redirect "/authorized"
  rescue StandardError => e
    log_error(e)
    session[:error] = "Publishing post failed: #{e.message}"
    redirect "/authorized"
  end

  get "/logout" do
    if session[:oauth_session_id]
      # Revoke access tokens and clean up the stored session
      settings.oauth_client.delete_session(session[:oauth_session_id], revoke: true)
    end

    session.clear
    session[:notice] = "Successfully logged out"
    redirect "/"
  end
end
