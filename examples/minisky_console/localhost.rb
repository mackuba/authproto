require 'authproto/insecure_http_client'
require 'authproto/localhost_server'
require 'authproto/minisky'
require 'dotenv/load'
require 'uri'

AuthProto.configure do |config|
  config.http_client = AuthProto::InsecureHTTPClient.new(timeout: 10)

  config.storage = AuthProto::Storage::SQLite.new(
    path: File.join(__dir__, "db", "localhost_auth.sqlite3")
  )
end

REDIRECT_URI = 'http://127.0.0.1:9292/callback'
SCOPE = 'atproto repo:app.bsky.feed.post rpc:app.bsky.feed.getTimeline?aud=*'
CLIENT_ID = 'http://localhost/?' + URI.encode_www_form({ redirect_uri: REDIRECT_URI, scope: SCOPE })

def create_client(pds)
  Minisky::OAuthClient.new(pds, client_id: CLIENT_ID, redirect_uri: REDIRECT_URI)
end

def authorize(client)
  auth = client.authorize(pds: "https://#{client.host}", scope: SCOPE)

  puts "Open this URL in the browser and complete authorization:"
  puts auth[:url]
  puts

  AuthProto::LocalhostServer.start(client.oauth_client.client_metadata) do |json|
    client.handle_callback(**json)
  end

  puts "Authentication complete ✓"
  puts "Your session id: #{auth[:session_id]}"
end
