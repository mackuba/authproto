# frozen_string_literal: true

require 'authproto/insecure_http_client'
require 'authproto/localhost_server'
require 'authproto/minisky'
require 'dotenv/load'

AuthProto.configure do |config|
  config.http_client = AuthProto::InsecureHTTPClient.new(timeout: 10)

  config.storage = AuthProto::Storage::SQLite.new(
    path: File.join(__dir__, "db", "localhost_auth.sqlite3")
  )
end

REDIRECT_URI = 'http://127.0.0.1:9292/callback'
SCOPE = 'atproto repo:app.bsky.feed.post rpc:app.bsky.feed.getTimeline?aud=*'

def create_client(session_id: nil)
  Minisky::OAuth.for_localhost(redirect_uri: REDIRECT_URI, scope: SCOPE, session_id: session_id)
end

def authorize(client, handle)
  auth = client.authorize(handle: handle, scope: SCOPE)

  puts "Open this URL in the browser and complete authorization:"
  puts auth[:url]
  puts

  AuthProto::LocalhostServer.start(client.oauth_client.client_metadata) do |json|
    client.handle_callback(json, expected_session_id: auth.fetch(:session_id))
  end

  puts "Authentication complete ✓"
  puts "Your session id: #{auth[:session_id]}"
end
