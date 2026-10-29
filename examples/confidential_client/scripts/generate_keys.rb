# frozen_string_literal: true

require 'jose'
require 'json'

key = JOSE::JWK.generate_key([:ec, "P-256"])

private_jwk = key.to_map.to_h.merge("kid" => "key-1", "use" => "sig")
public_jwk = key.to_public.to_map.to_h.merge("kid" => "key-1", "use" => "sig")

config_dir = File.expand_path('../config', __dir__)
private_path = File.join(config_dir, 'keys.json')

File.open(private_path, File::WRONLY | File::CREAT | File::TRUNC, 0o600) do |file|
  file.chmod(0o600)
  file.write(JSON.pretty_generate('keys' => [private_jwk]) + "\n")
end

File.write(File.join(config_dir, 'public-keys.json'), JSON.pretty_generate('keys' => [public_jwk]) + "\n")

puts "Private keys saved to config/keys.json; publish only config/public-keys.json in metadata."
