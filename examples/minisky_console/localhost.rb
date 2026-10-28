require 'atproto_auth/minisky'
require 'dotenv/load'
require 'uri'

AuthProto.configure do |config|
  config.http_client = AuthProto::InsecureHTTPClient.new(timeout: 10)

  config.storage = AuthProto::Storage::SQLite.new(
    path: File.join(__dir__, "db", "localhost_auth.sqlite3")
  )
end

$metadata = {
  'application_type' => 'native',
  'client_id' => 'http://localhost/',
  'client_name' => 'AT Protocol OAuth Ruby Example',
  'redirect_uris' => ['http://127.0.0.1:9292/callback'],
  'grant_types' => ['authorization_code', 'refresh_token'],
  'response_types' => ['code'],
  'scope' => 'atproto repo:app.bsky.feed.post rpc:app.bsky.feed.getTimeline?aud=*',
  'token_endpoint_auth_method' => 'none',
  'dpop_bound_access_tokens' => true,
}

$client_id = $metadata['client_id'] + '?' + URI.encode_www_form({
  redirect_uri: $metadata['redirect_uris'][0],
  scope: $metadata['scope']
})

$metadata['client_id'] = $client_id

def create_client(pds)
  Minisky::OAuthClient.new(pds,
    client_id: $client_id,
    redirect_uri: $metadata['redirect_uris'][0],
    metadata: $metadata
  )
end

def authorize(client)
  auth = client.authorize(pds_url: "https://#{client.host}", scope: $metadata['scope'])

  puts "Open this URL in the browser and complete authorization:"
  puts auth[:url]
  puts

  AuthProto::LocalhostServer.start($metadata) do |json|
    client.handle_callback(**json)
  end

  puts "Authentication complete ✓"
  puts "Your session id: #{auth[:session_id]}"
end
