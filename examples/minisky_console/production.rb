# frozen_string_literal: true

require 'authproto/minisky'
require 'dotenv/load'
require 'uri'

AuthProto.configure do |config|
  config.http_client = AuthProto::HTTPClient.new(timeout: 10)

  config.storage = AuthProto::Storage::SQLite.new(
    path: File.join(__dir__, "db", "production_auth.sqlite3")
  )
end

def create_client(server_hostname, session_id: nil)
  Minisky::OAuth.new(
    client_id: "https://#{server_hostname}/oauth-client-metadata.json",
    redirect_uri: "https://#{server_hostname}/callback",
    session_id: session_id
  )
end

def authorize(client, handle)
  auth = client.authorize(handle: handle, scope: client.oauth_client.client_metadata.scope)

  puts "Open this URL in the browser and complete authorization:"
  puts auth[:url]
end

def handle_callback(client, json)
  # Use the ID retained by this local client, not a value copied from the callback page.
  result = client.handle_callback(json, expected_session_id: client.session_id)

  puts "Authentication complete ✓"
  puts "Your session id: #{result[:session_id]}"
end
