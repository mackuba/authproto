# frozen_string_literal: true

require 'cgi'
require 'json'
require 'securerandom'
require 'time'
require 'uri'

require 'authproto'
require 'dotenv/load'
require 'faraday'
require 'sinatra/base'
require 'sinatra/reloader'

session_secret = ENV.fetch("SESSION_SECRET") { SecureRandom.hex(32) }
raise "SESSION_SECRET must be at least 64 characters long (got: #{session_secret})" unless session_secret.length >= 64

# Main app entry point
class ExampleApp < Sinatra::Base
  def check_stored_session(session_id)
    return false unless session_id

    settings.oauth_client.authorized?(session_id)
  rescue AuthProto::SessionError
    false
  end

  configure :development do
    register Sinatra::Reloader
  end

  # Initialize the AT Protocol OAuth client
  configure do
    # Configure AuthProto settings
    AuthProto.configure do |config|
      config.http_client = AuthProto::HTTPClient.new(timeout: 10, verify_ssl: true)
      config.default_token_lifetime = 300
      config.dpop_nonce_lifetime = 300

      case ENV.fetch("STORAGE_BACKEND", "memory")
      when "memory"
        config.storage = AuthProto::Storage::Memory.new
      when "sqlite"
        config.storage = AuthProto::Storage::SQLite.new(
          path: ENV.fetch("SQLITE_PATH", File.join(__dir__, "db", "authproto.sqlite3"))
        )
      when "redis"
        config.storage = AuthProto::Storage::Redis.new(
          redis_client: Redis.new(url: ENV.fetch("REDIS_URL"))
        )
      else
        raise "STORAGE_BACKEND must be memory, sqlite, or redis"
      end
    end

    # Load client metadata
    metadata_path = File.join(__dir__, "config", "oauth-client-metadata.json")
    metadata = JSON.parse(File.read(metadata_path))

    client_id = metadata['client_id']

    if client_id.chomp("/") == "http://localhost"
      scope = CGI.escape(metadata['scope'])
      redirect_uri = CGI.escape(metadata['redirect_uris'][0])
      client_id += "?scope=#{scope}&redirect_uri=#{redirect_uri}"
    end

    # Private client-authentication keys are kept outside public metadata.
    signing_key = JSON.parse(File.read(File.join(__dir__, "config", "keys.json")))["keys"].first

    # Create OAuth client
    set :oauth_client, AuthProto::Client.new(
      client_id: client_id,
      redirect_uri: metadata['redirect_uris'][0],
      metadata: metadata,
      signing_key: signing_key,
      dpop_key: signing_key
    )
  end

  set :host_authorization, {
    permitted_hosts: ["localhost", ENV.fetch("PERMITTED_DOMAIN", nil)].compact
  }

  use Rack::Session::Cookie,
      key: "atproto.session",
      expire_after: 86_400, # 1 day in seconds
      secret: session_secret,
      secure: ENV.fetch("RACK_ENV", "development") == "production",  # Only send over HTTPS
      httponly: true,     # Not accessible via JavaScript
      same_site: :lax     # CSRF protection

  helpers do
    def recover_session
      session_id = session[:oauth_session_id]
      return nil unless session_id

      begin
        # Check if session is still valid
        return nil unless settings.oauth_client.authorized?(session_id)

        session_id
      rescue AuthProto::Client::SessionError
        # Clear invalid session
        session.delete(:oauth_session_id)
        nil
      end
    end
  end

  get "/" do
    # Check for existing session
    redirect "/authorized" if recover_session

    erb :index
  end

  get "/oauth-client-metadata.json" do
    content_type :json

    # Read metadata from config file
    metadata_path = File.join(__dir__, "config", "oauth-client-metadata.json")
    metadata = JSON.parse(File.read(metadata_path))

    # This file contains only the public counterparts of config/keys.json.
    JSON.generate(metadata)
  end

  # Start OAuth flow
  post "/auth" do
    handle = params[:handle]

    begin
      # Start authorization flow
      auth = settings.oauth_client.authorize(
        handle: handle,
        scope: "atproto repo:app.bsky.feed.post"
      )

      # Store session ID in user's browser session
      session[:oauth_session_id] = auth[:session_id]

      # Redirect to authorization URL
      redirect auth[:url]
    rescue StandardError => e
      session[:error] = "Authorization failed: #{e.message}"
      redirect "/"
    end
  end

  # OAuth callback handler
  get "/callback" do
    # Handle the callback
    result = settings.oauth_client.handle_callback(
      code: params[:code],
      state: params[:state],
      iss: params[:iss]
    )

    # Store tokens
    session[:oauth_session_id] = result[:session_id]

    redirect "/authorized"
  rescue StandardError => e
    session[:error] = "Callback failed: #{e.message}"
    redirect "/"
  end

  # Show authorized state and test API call
  get "/authorized" do
    session_id = session[:oauth_session_id]
    return redirect "/" unless check_stored_session(session_id)

    begin
      # Get current session tokens
      oauth_session = settings.oauth_client.get_tokens(session_id)

      # Check if token needs refresh
      if oauth_session[:expires_in] < 30
        # Refresh token
        oauth_session = settings.oauth_client.refresh_token(session_id)
      end

      # Make test API call to com.atproto.identity.resolveHandle
      conn = Faraday.new(url: "https://api.bsky.app") do |f|
        f.request :json
        f.response :json
      end

      # Get auth headers for request
      headers = settings.oauth_client.auth_headers(
        session_id: session_id,
        method: 'GET',
        url: "https://api.bsky.app/xrpc/com.atproto.identity.resolveHandle"
      )

      # Make authenticated request
      response = conn.get("/xrpc/com.atproto.identity.resolveHandle") do |req|
        headers.each { |k, v| req.headers[k] = v }
        req.params[:handle] = "bsky.app"
      end

      @api_result = response.body
      @session = oauth_session
      erb :authorized
    rescue StandardError => e
      session[:error] = "API call failed: #{e.message}"
      redirect "/"
    end
  end

  post "/posts" do
    session_id = session[:oauth_session_id]
    return redirect "/" unless check_stored_session(session_id)

    text = params[:text].to_s
    if text.strip.empty?
      session[:error] = "Post text cannot be empty"
      return redirect "/authorized"
    end

    if text.length > 300 || text.bytesize > 3_000
      session[:error] = "Post text must be at most 300 characters and 3,000 bytes"
      return redirect "/authorized"
    end

    oauth_session = settings.oauth_client.session_manager.get_session(session_id)

    pds_url = ENV['PDS_URL'] || DIDKit::DID.new(oauth_session.did).document.pds_endpoint
    raise "No HTTPS PDS location found" unless pds_url && URI(pds_url).is_a?(URI::HTTPS)

    endpoint = URI.join(
      "#{pds_url.chomp("/")}/",
      "xrpc/com.atproto.repo.createRecord"
    ).to_s

    headers = settings.oauth_client.auth_headers(
      session_id: session_id,
      method: 'POST',
      url: endpoint
    )

    conn = Faraday.new do |f|
      f.request :json
      f.response :json
    end
    response = conn.post(endpoint) do |req|
      headers.each { |key, value| req.headers[key] = value }
      req.body = {
        repo: oauth_session.did,
        collection: "app.bsky.feed.post",
        record: {
          "$type": "app.bsky.feed.post",
          text: text,
          langs: ["en"],
          createdAt: Time.now.utc.iso8601(3)
        }
      }
    end

    unless response.success?
      error_body = response.body.is_a?(String) ? response.body : JSON.generate(response.body)
      raise "PDS rejected post (#{response.status}): #{error_body}"
    end

    session[:notice] = "Post published successfully"
    redirect "/authorized"
  rescue StandardError => e
    session[:error] = "Publishing post failed: #{e.message}"
    redirect "/authorized"
  end

  get "/signout" do
    if session[:oauth_session_id]
      # Clean up stored session
      settings.oauth_client.delete_session(session[:oauth_session_id])
    end

    session.clear
    session[:notice] = "Successfully signed out"
    redirect "/"
  end

  # Helper method to check if user is authenticated
  def authenticated?
    return false unless session[:tokens]

    settings.oauth_client.authorized?(session[:tokens][:session_id])
  end
end
