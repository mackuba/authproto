# frozen_string_literal: true

describe AuthProto::Client, 'redirect URI matching' do
  ['http://localhost', 'http://localhost/?scope=atproto'].each do |client_id|
    it "should reject preloaded metadata for #{client_id}" do
      metadata = {
        'client_id' => client_id,
        'application_type' => 'native',
        'redirect_uris' => ['http://127.0.0.1/'],
        'grant_types' => ['authorization_code'],
        'response_types' => ['code'],
        'scope' => 'atproto',
        'token_endpoint_auth_method' => 'none',
        'dpop_bound_access_tokens' => true
      }

      expect {
        described_class.new(client_id: client_id, redirect_uri: 'http://127.0.0.1/', metadata: metadata)
      }.to raise_error(AuthProto::InvalidClientMetadata, /For localhost clients/)
    end
  end

  ['127.0.0.1', '[::1]'].each do |host|
    it "should accept a dynamic port for the default #{host} development callback" do
      redirect_uri = "http://#{host}:54321/"
      client = described_class.new(client_id: 'http://localhost', redirect_uri: redirect_uri)

      client.redirect_uri.should == redirect_uri
    end

    it "should ignore an explicitly declared port for the #{host} development callback" do
      registered_uri = "http://#{host}:12345/callback?flow=login"
      client_id = "http://localhost?#{URI.encode_www_form('redirect_uri' => registered_uri)}"
      redirect_uri = "http://#{host}:54321/callback?flow=login"
      client = described_class.new(client_id: client_id, redirect_uri: redirect_uri)

      client.redirect_uri.should == redirect_uri
    end
  end

  ['http://localhost:54321/', 'http://0.0.0.0:54321/', 'http://127.0.0.2:54321/',
   'https://127.0.0.1:54321/', 'http://127.0.0.1:54321/callback', 'http://127.0.0.1:54321/?extra=true',
   'http://127.0.0.1:54321/#fragment', 'http://user@127.0.0.1:54321/', 'http://@127.0.0.1:54321/',
   'http://127.0.0.1:0/', 'http://127.0.0.1:65536/', 'http://127.0.0.1:invalid/', 'invalid URI'].each do |uri|
    it "should reject an unregistered or invalid development callback #{uri.inspect}" do
      expect {
        described_class.new(client_id: 'http://localhost', redirect_uri: uri)
      }.to raise_error(AuthProto::Error, /redirect_uri not found/)
    end
  end

  ['http://[::1]:54321/callback?flow=login', 'http://127.0.0.1:54321/other?flow=login',
   'http://127.0.0.1:54321/callback?flow=other'].each do |uri|
    it "should match all development callback components except the port for #{uri.inspect}" do
      registered_uri = 'http://127.0.0.1:12345/callback?flow=login'
      client_id = "http://localhost?#{URI.encode_www_form('redirect_uri' => registered_uri)}"

      expect {
        described_class.new(client_id: client_id, redirect_uri: uri)
      }.to raise_error(AuthProto::Error, /redirect_uri not found/)
    end
  end

  ['web', 'native'].each do |application_type|
    it "should require exact callback membership for an HTTPS #{application_type} client ID" do
      registered_uri = if application_type == 'native'
        'http://127.0.0.1:12345/callback'
      else
        'https://client.example.com:12345/callback'
      end
      metadata = {
        'client_id' => 'https://client.example.com/metadata.json',
        'application_type' => application_type,
        'redirect_uris' => [registered_uri],
        'grant_types' => ['authorization_code'],
        'response_types' => ['code'],
        'scope' => 'atproto',
        'token_endpoint_auth_method' => 'none',
        'dpop_bound_access_tokens' => true
      }

      expect {
        described_class.new(client_id: metadata['client_id'], metadata: metadata,
                            redirect_uri: registered_uri.sub(':12345/', ':54321/'))
      }.to raise_error(AuthProto::Error, /redirect_uri not found/)
    end
  end
end
