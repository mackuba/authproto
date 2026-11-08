# frozen_string_literal: true

require 'securerandom'
require 'sinatra/base'
require 'sinatra/reloader'

require_relative 'init'
require_relative 'bookmark'


#
# A server-rendered OAuth example that caches and searches private Bluesky bookmarks.
#

class BookmarksApp < Sinatra::Base
  PER_PAGE = 20

  configure :development do
    register Sinatra::Reloader
  end

  configure do
    set :root, File.expand_path('..', __dir__)
    set :host_authorization, permitted_hosts: ['localhost', '127.0.0.1', '[::1]', ENV['PERMITTED_DOMAIN']].compact

    session_secret = ENV.fetch('SESSION_SECRET') { SecureRandom.hex(32) }
    raise "SESSION_SECRET must be at least 64 characters long" if session_secret.length < 64

    master_key = ENV['ATPROTO_MASTER_KEY']
    raise "ATPROTO_MASTER_KEY must be set" if master_key.nil?

    use Rack::Session::Cookie,
      key: 'bookmarks.session',
      expire_after: 86_400,
      secret: session_secret,
      secure: production?,
      httponly: true,
      same_site: :lax

    use Rack::Protection::AuthenticityToken
  end

  helpers do
    def current_session
      @current_session ||= begin
        session_id = session[:oauth_session_id]
        return nil unless session_id

        oauth_session = OAuth.client.get_session(session_id)

        if oauth_session.nil? || oauth_session.pending?
          session.delete(:oauth_session_id)
          return nil
        end

        oauth_session
      end
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
      puts "Handle lookup failed: #{e.class}: #{e.message}"
      nil
    end

    def report_error(message, error)
      puts "#{message}: #{error.class}: #{error.message}"
      puts error.backtrace.take_while { |l| !l.include?('/lib/sinatra/base') }

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

    File.read(OAuth.metadata_path)
  end

  post '/authenticate' do
    auth = OAuth.client.authorize(handle: params[:handle].to_s.strip, scope: OAuth.metadata['scope'])

    session[:pending_oauth_session_id] = auth.fetch(:session_id)
    redirect auth.fetch(:url)
  rescue StandardError => e
    report_error("Authorization failed", e)
    redirect '/'
  end

  get '/callback' do
    pending_session_id = session.delete(:pending_oauth_session_id)

    result = OAuth.client.handle_callback(params, expected_session_id: pending_session_id)

    session[:oauth_session_id] = result.session_id
    session[:handle] = lookup_handle(result.did)

    AuthProto.storage.set("atproto:bookmarks:session:#{result.did}", result.session_id)
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

    count = Bookmark.fetch_bookmarks(current_session.session_id)

    session[:notice] = "Fetched #{count} bookmarks."
    redirect '/bookmarks'
  rescue StandardError => e
    report_error("Fetching bookmarks failed", e)
    redirect '/bookmarks'
  end

  post '/logout' do
    require_login

    did = current_session.did
    session_id = current_session.session_id

    OAuth.client.delete_session(session_id, revoke: true)

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
