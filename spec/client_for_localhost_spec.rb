# frozen_string_literal: true

describe AuthProto::Client, '.for_localhost' do
  it "should encode callback and scope query parameters without changing their values" do
    redirect_uri = 'http://127.0.0.1:3000/callback?flow=login&next=%2Fhome'
    scope = 'atproto repo:app.bsky.feed.post rpc:app.bsky.feed.getTimeline?aud=*'
    client = described_class.for_localhost(redirect_uri: redirect_uri, scope: scope)
    client_id = URI(client.client_id)

    client_id.scheme.should == 'http'
    client_id.host.should == 'localhost'
    client_id.path.should == '/'
    client_id.port.should == 80
    URI.decode_www_form(client_id.query).should == [['redirect_uri', redirect_uri], ['scope', scope]]
    client.redirect_uri.should == redirect_uri
    client.client_metadata.redirect_uris.should == [redirect_uri]
    client.client_metadata.scope.should == scope
    client.client_metadata.should_not be_confidential
  end

  it "should accept a frozen IPv6 callback URI and default the scope to atproto" do
    redirect_uri = URI('http://[::1]:3000/callback').freeze
    client = described_class.for_localhost(redirect_uri: redirect_uri)

    client.redirect_uri.should == redirect_uri.to_s
    client.client_metadata.redirect_uris.should == [redirect_uri.to_s]
    client.client_metadata.scope.should == 'atproto'
  end

  ['http://localhost:3000/callback', 'http://example.com/callback'].each do |redirect_uri|
    it "should validate the callback URL #{redirect_uri}" do
      expect {
        described_class.for_localhost(redirect_uri: redirect_uri)
      }.to raise_error(AuthProto::InvalidClientMetadata)
    end
  end

  ['repo:app.bsky.feed.post', 'atproto  repo:app.bsky.feed.post'].each do |scope|
    it "should validate the scope #{scope.inspect}" do
      expect {
        described_class.for_localhost(redirect_uri: 'http://127.0.0.1:3000/callback', scope: scope)
      }.to raise_error(AuthProto::InvalidClientMetadata)
    end
  end
end
