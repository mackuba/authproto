# frozen_string_literal: true

describe AuthProto::Client, 'client authentication keys' do
  let(:private_jwk) do
    JOSE::JWK.generate_key([:ec, 'P-256']).to_map.to_h.merge('kid' => 'client-key', 'key_ops' => ['sign'])
  end
  let(:public_jwk) { private_jwk.except('d').merge('key_ops' => ['verify']) }
  let(:metadata) do
    { 'client_id' => 'https://client.example.com/metadata.json',
      'redirect_uris' => ['https://client.example.com/callback'],
      'grant_types' => ['authorization_code', 'refresh_token'], 'response_types' => ['code'],
      'scope' => 'atproto', 'dpop_bound_access_tokens' => true,
      'token_endpoint_auth_method' => 'private_key_jwt', 'token_endpoint_auth_signing_alg' => 'ES256',
      'jwks' => { 'keys' => [public_jwk] } }
  end

  def build_client(key)
    described_class.new(client_id: metadata['client_id'], redirect_uri: metadata['redirect_uris'].first,
                        metadata: metadata, signing_key: key)
  end

  it 'should accept a private JWK separately from matching public metadata' do
    client = build_client(private_jwk)
    client.client_metadata.jwks['keys'].first.should_not have_key('d')
    client.client_metadata.jwks['keys'].first['key_ops'].should == ['verify']
  end

  it 'should accept a JOSE signing key' do
    build_client(JOSE::JWK.from_map(private_jwk)).client_metadata.should be_confidential
  end

  it 'should require a private signing key for confidential clients' do
    expect { build_client(nil) }.to raise_error(AuthProto::InvalidClientMetadata, /require a signing_key/)
  end

  it 'should reject a public key supplied as the private signing key' do
    expect { build_client(public_jwk) }.to raise_error(
      AuthProto::PAR::ClientAssertion::Error, /signing_key must be a private key/
    )
  end

  it 'should match key material as well as kid' do
    metadata['jwks']['keys'] = [JOSE::JWK.generate_key([:ec, 'P-256']).to_public.to_map.to_h.merge('kid' => 'client-key')]
    expect { build_client(private_jwk) }.to raise_error(AuthProto::InvalidClientMetadata, /match an active public key/)
  end

  it 'should find the advertised key even if it is not the first entry' do
    other = JOSE::JWK.generate_key([:ec, 'P-256']).to_public.to_map.to_h.merge('kid' => 'other')
    metadata['jwks']['keys'].unshift(other)
    build_client(private_jwk).client_metadata.should be_confidential
  end

  it 'should accept other advertised keys with encryption usage and different algorithms' do
    encryption_key = JOSE::JWK.generate_key([:rsa, 2048]).to_public.to_map.to_h.merge(
      'kid' => 'encryption', 'use' => 'enc', 'key_ops' => ['encrypt', 'wrapKey'], 'alg' => 'RSA-OAEP'
    )
    metadata['jwks']['keys'].unshift(encryption_key)
    build_client(private_jwk).client_metadata.jwks['keys'].length.should == 2
  end

  it 'should accept a matching key without optional usage declarations' do
    metadata['jwks']['keys'].first.delete('key_ops')
    build_client(private_jwk).client_metadata.should be_confidential
  end

  [{ 'use' => 'enc' }, { 'key_ops' => ['encrypt'] }, { 'key_ops' => ['wrapKey'] }].each do |usage|
    it "should reject a matching public key that does not permit verification #{usage.inspect}" do
      metadata['jwks']['keys'] = [public_jwk.except('key_ops').merge(usage)]
      expect { build_client(private_jwk) }.to raise_error(AuthProto::InvalidClientMetadata, /match an active public key/)
    end
  end

  [{ 'kid' => 'other' }, { 'revoked' => true }, { 'alg' => 'ES384' }].each do |changes|
    it "should reject an unadvertised or inactive key #{changes.inspect}" do
      metadata['jwks']['keys'].first.merge!(changes)
      expect { build_client(private_jwk) }.to raise_error(AuthProto::InvalidClientMetadata, /match an active public key/)
    end
  end

  [{ 'kid' => '' }, { 'd' => '' }, { 'alg' => 'ES384' }, { 'revoked' => true },
   { 'use' => 'enc' }, { 'key_ops' => ['verify'] }].each do |changes|
    it "should reject an unusable private signing key #{changes.inspect}" do
      expect { build_client(private_jwk.merge(changes)) }.to raise_error(AuthProto::PAR::ClientAssertion::Error)
    end
  end

  it 'should reject a signing key for a public client' do
    metadata['token_endpoint_auth_method'] = 'none'
    metadata.delete('token_endpoint_auth_signing_alg')
    expect { build_client(private_jwk) }.to raise_error(AuthProto::InvalidClientMetadata, /Public clients/)
  end

  it 'should use a separate signing key with jwks_uri without fetching private material' do
    metadata.delete('jwks')
    metadata['jwks_uri'] = 'https://client.example.com/keys.json'
    AuthProto.configuration.http_client.expects(:get).never if AuthProto.configuration.http_client
    build_client(private_jwk).client_metadata.jwks_uri.should == metadata['jwks_uri']
  end
end
