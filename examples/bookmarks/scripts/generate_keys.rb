# frozen_string_literal: true

require 'jose'
require 'json'

metadata_path = File.expand_path('../config/oauth-client-metadata.json', __dir__)
keys_path = File.expand_path('../config/keys.json', __dir__)
metadata = JSON.parse(File.read(metadata_path))

unless metadata['client_id'].start_with?('https://')
  abort "Confidential clients require an HTTPS client_id on a live domain"
end

abort "config/keys.json already exists; remove it explicitly to generate a new key" if File.exist?(keys_path)

key = JOSE::JWK.generate_key([:ec, 'P-256'])
attributes = { 'kid' => "key-#{Time.now.to_i}", 'use' => 'sig' }
private_jwk = key.to_map.to_h.merge(attributes)
public_jwk = key.to_public_map.to_h.merge(attributes)

File.write(keys_path, JSON.pretty_generate('keys' => [private_jwk]) + "\n", perm: 0o600)
metadata['token_endpoint_auth_method'] = 'private_key_jwt'
metadata['token_endpoint_auth_signing_alg'] = 'ES256'
metadata['jwks'] = { 'keys' => [public_jwk] }
File.write(metadata_path, JSON.pretty_generate(metadata) + "\n")

puts "Saved config/keys.json and added its public key to config/oauth-client-metadata.json."
