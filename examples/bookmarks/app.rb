# frozen_string_literal: true

require 'authproto'
require 'authproto/minisky'
require 'didkit'
require 'dotenv/load'
require 'json'
require 'securerandom'
require 'sinatra/activerecord'
require 'sinatra/base'
require 'sinatra/reloader'
require 'time'
require 'uri'

require_relative 'bookmark'


#
# A server-rendered OAuth example that caches and searches private Bluesky bookmarks.
#

class BookmarksApp < Sinatra::Base
  SCOPE = 'atproto rpc:app.bsky.bookmark.getBookmarks?aud=*'
  PER_PAGE = 20

  register Sinatra::ActiveRecordExtension

  configure :development do
    register Sinatra::Reloader
  end

  configure do
    set :root, __dir__
    set :database, adapter: 'sqlite3',
                   database: ENV.fetch('BOOKMARKS_DATABASE', File.join(__dir__, 'db', 'bookmarks.sqlite3')),
                   timeout: 5_000
    set :metadata_path, ENV.fetch('OAUTH_METADATA_PATH', File.join(__dir__, 'config', 'oauth-client-metadata.json'))

    unless File.exist?(metadata_path)
      raise "Copy a metadata template to config/oauth-client-metadata.json before starting the app"
    end

    metadata = JSON.parse(File.read(metadata_path))
    raise "Client metadata must request only #{SCOPE}" unless metadata['scope'] == SCOPE

    AuthProto.configure do |config|
      config.http_client = AuthProto::HTTPClient.new(timeout: 10)
      config.storage = AuthProto::Storage::SQLite.new(
        path: ENV.fetch('AUTHPROTO_DATABASE', File.join(__dir__, 'db', 'authproto.sqlite3'))
      )
    end

    client_id = metadata.fetch('client_id')
    redirect_uri = metadata.fetch('redirect_uris').first
    options = { client_id: client_id, redirect_uri: redirect_uri }

    if client_id.match?(%r{\Ahttp://localhost(/|$)})
      options[:client_id] = 'http://localhost/?' + URI.encode_www_form(redirect_uri: redirect_uri, scope: SCOPE)
    else
      options[:metadata] = metadata
      keys_path = File.join(__dir__, 'config', 'keys.json')
      options[:signing_key] = JSON.parse(File.read(keys_path)).fetch('keys').first if File.exist?(keys_path)
    end

    set :oauth_options, options
    set :oauth_client, Minisky::OAuthClient.new('https://bsky.social', **options).oauth_client
    set :host_authorization, permitted_hosts: ['localhost', '127.0.0.1', '[::1]', ENV['PERMITTED_DOMAIN']].compact

    session_secret = ENV.fetch('SESSION_SECRET') { SecureRandom.hex(32) }
    raise "SESSION_SECRET must be at least 64 characters long" if session_secret.length < 64

    use Rack::Session::Cookie,
        key: 'bookmarks.session',
        expire_after: 86_400,
        secret: session_secret,
        secure: production?,
        httponly: true,
        same_site: :lax
    use Rack::Protection::AuthenticityToken
  end

  # Creates a separate Minisky client for a stored OAuth session.
  #
  # @param session_id [String, nil] session to resume, or `nil` to start authorization
  # @return [Minisky::OAuthClient] client targeting the account's PDS
  #
  def self.api_client(session_id = nil)
    oauth_session = settings.oauth_client.session_manager.get_session(session_id) if session_id
    host = oauth_session ? oauth_session.pds : 'https://bsky.social'

    Minisky::OAuthClient.new(host, **settings.oauth_options, session_id: session_id)
  end

  # Fetches bookmarks synchronously, following API cursors and saving text posts.
  # A failed fetch rolls back the import so an incremental retry cannot miss older pages.
  #
  # @param session_id [String] OAuth session belonging to the bookmark owner
  # @param newer_only [Boolean] stop at the newest locally saved bookmark
  # @return [Integer] number of imported bookmarks
  # @raise [Minisky::AuthError] if the session cannot be resumed
  #
  def self.fetch_bookmarks(session_id, newer_only: false)
    client = api_client(session_id)
    client.check_access
    oauth_session = client.oauth_client.session_manager.get_session(session_id)
    did = oauth_session.did
    newest = Bookmark.where(did: did).maximum(:created_at) if newer_only
    imported = 0
    cursor = nil

    Bookmark.transaction do
      loop do
        query = { limit: 100 }
        query[:cursor] = cursor if cursor
        response = client.get_request('app.bsky.bookmark.getBookmarks', query,
                                      headers: { 'atproto-proxy' => 'did:web:api.bsky.app#bsky_appview' })
        reached_newest = false

        response.fetch('bookmarks').each do |entry|
          created_at = entry['createdAt'] && Time.iso8601(entry['createdAt'])

          if newest && created_at && created_at <= newest
            reached_newest = true
            next
          end

          post = entry.fetch('item')
          next unless post['$type'] == 'app.bsky.feed.defs#postView'

          record = post.fetch('record')
          next if record['text'].blank?

          bookmark = Bookmark.find_or_initialize_by(did: did, uri: entry.fetch('subject').fetch('uri'))
          bookmark.update!(
            author_handle: post.fetch('author').fetch('handle'),
            created_at: created_at,
            posted_at: Time.iso8601(record.fetch('createdAt')),
            text: record.fetch('text')
          )
          imported += 1
        end

        cursor = response['cursor']
        break if cursor.blank? || reached_newest
      end
    end

    AuthProto.storage.set("atproto:bookmarks:fetched:#{did}", 'true')
    imported
  end

  helpers do
    def current_session
      return @current_session if defined?(@current_session)

      session_id = session[:oauth_session_id]
      oauth_session = session_id && settings.oauth_client.session_manager.get_session(session_id)
      @current_session = oauth_session unless oauth_session&.pending?

      session.delete(:oauth_session_id) if @current_session.nil?

      @current_session
    end

    def require_login
      redirect '/' unless current_session
    end

    def html_escape(text)
      Rack::Utils.escape_html(text)
    end

    def csrf_token
      Rack::Protection::AuthenticityToken.token(session)
    end

    def lookup_handle(did)
      DID.new(did).get_verified_handle
    rescue StandardError => e
      logger.warn("Handle lookup failed: #{e.class}: #{e.message}")
      nil
    end

    def report_error(message, error)
      logger.error("#{message}: #{error.class}: #{error.message}")
      session[:error] = "#{message}: #{error.message}"
    end
  end

  before do
    cache_control :no_store
  end

  get '/' do
    redirect '/bookmarks' if current_session

    erb :index
  end

  get '/oauth-client-metadata.json' do
    content_type :json

    File.read(settings.metadata_path)
  end

  post '/authenticate' do
    auth = self.class.api_client.authorize(handle: params[:handle].to_s.strip, scope: SCOPE)

    session[:pending_oauth_session_id] = auth.fetch(:session_id)
    redirect auth.fetch(:url)
  rescue StandardError => e
    report_error("Authorization failed", e)
    redirect '/'
  end

  get '/callback' do
    result = self.class.api_client.handle_callback(
      params,
      expected_session_id: session.delete(:pending_oauth_session_id)
    )

    session[:oauth_session_id] = result.fetch(:session_id)
    session[:handle] = lookup_handle(result.fetch(:did))

    AuthProto.storage.set("atproto:bookmarks:session:#{result.fetch(:did)}", result.fetch(:session_id))
    redirect '/bookmarks'
  rescue StandardError => e
    report_error("Authorization failed", e)
    redirect '/'
  end

  get '/bookmarks' do
    require_login

    @query = params[:q].to_s.strip
    @fetched = AuthProto.storage.get("atproto:bookmarks:fetched:#{current_session.did}")

    bookmarks = Bookmark.where(did: current_session.did).newest_first

    if @query.empty?
      @total_pages = [(bookmarks.count.to_f / PER_PAGE).ceil, 1].max
      @page = params[:page].to_i.clamp(1, @total_pages)
      first_page = (@page - 2).clamp(1, [@total_pages - 4, 1].max)
      @page_numbers = first_page..[first_page + 4, @total_pages].min
      @bookmarks = bookmarks.limit(PER_PAGE).offset((@page - 1) * PER_PAGE)
    else
      pattern = "%#{Bookmark.sanitize_sql_like(@query)}%"
      @bookmarks = bookmarks.where("text LIKE ? ESCAPE '\\'", pattern)
    end

    erb :bookmarks
  end

  post '/fetch' do
    require_login

    count = self.class.fetch_bookmarks(current_session.session_id)

    session[:notice] = "Fetched #{count} bookmarks with text."
    redirect '/bookmarks'
  rescue StandardError => e
    report_error("Fetching bookmarks failed", e)
    redirect '/bookmarks'
  end

  post '/logout' do
    require_login

    did = current_session.did
    session_id = current_session.session_id

    settings.oauth_client.delete_session(session_id, revoke: true)

    if AuthProto.storage.get("atproto:bookmarks:session:#{did}") == session_id
      AuthProto.storage.delete("atproto:bookmarks:session:#{did}")
    end

    session.clear
    redirect '/'
  rescue StandardError => e
    report_error("Logging out failed", e)
    redirect '/bookmarks'
  end
end
