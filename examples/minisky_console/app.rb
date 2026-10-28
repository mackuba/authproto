# frozen_string_literal: true

require 'dotenv/load'
require 'json'
require 'sinatra'

$server_host = ENV.fetch('SERVER_HOST')

$metadata = {
  'application_type' => 'native',
  'client_id' => "https://#{$server_host}/oauth-client-metadata.json",
  'client_name' => 'Minisky OAuth Example App',
  'redirect_uris' => ["https://#{$server_host}/callback"],
  'grant_types' => ['authorization_code', 'refresh_token'],
  'response_types' => ['code'],
  'scope' => 'atproto repo:app.bsky.feed.post rpc:app.bsky.feed.getTimeline?aud=*',
  'token_endpoint_auth_method' => 'none',
  'dpop_bound_access_tokens' => true,
}

get "/" do
  content_type 'text/plain'

  "To start authentication, run this in bin/console:\n\n" +
  "require_relative 'production'\n" +
  "client = create_client('#{$server_host}', 'target.pds.hostname')\n" +
  "authorize(client)\n\n" +
  "Then open the printed URL and authorize the app. You will receive a hash with data, which you need to paste to:\n\n" +
  "handle_callback(client, { ... })\n"
end

get "/oauth-client-metadata.json" do
  content_type :json

  JSON.generate($metadata) + "\n"
end

get "/callback" do
  content_type 'text/plain'

  if params[:error]
    params.slice(:error, :error_description).to_json
  elsif params[:code] && params[:state] && params[:iss]
    "To complete authentication, run this in the console where you started the authentication flow " +
    "(replace \"client\" with the local variable name you've used):\n\n" +
    "handle_callback(client, #{params.slice(:code, :state, :iss).map { |k, v| [k.to_sym, v] }.to_h.inspect})\n"
  else
    "Missing params"
  end
end
