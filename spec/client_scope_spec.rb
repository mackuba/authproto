# frozen_string_literal: true

describe AuthProto::Client, 'requested scopes' do
  let(:metadata) do
    {
      'client_id' => 'https://client.example.com/metadata.json',
      'redirect_uris' => ['https://client.example.com/callback'],
      'grant_types' => ['authorization_code'],
      'response_types' => ['code'],
      'scope' => 'atproto repo:app.bsky.feed.post rpc:app.bsky.feed.getTimeline?aud=*',
      'token_endpoint_auth_method' => 'none',
      'dpop_bound_access_tokens' => true
    }
  end
  let(:client) do
    described_class.new(client_id: metadata['client_id'], redirect_uri: metadata['redirect_uris'].first,
                        metadata: metadata)
  end

  [nil, 123, ['atproto'], '', ' atproto', 'atproto ', 'atproto  repo:app.bsky.feed.post',
   "atproto\trepo:app.bsky.feed.post", "atproto\n", 'atproto "quoted"', 'atproto back\\slash',
   'atproto café', "atproto \xFF"].each do |scope|
    it "should reject invalid scope syntax #{scope.inspect} before discovery or session creation" do
      client.expects(:resolve_auth_server).never
      client.session_manager.expects(:create_session).never

      expect { client.authorize(pds: 'https://pds.example.com', scope: scope) }.to raise_error(
        AuthProto::Error, /scope must contain valid tokens/
      )
    end
  end

  it "should require the exact atproto token" do
    expect { client.authorize(pds: 'https://pds.example.com', scope: 'repo:app.bsky.feed.post') }.to raise_error(
      AuthProto::Error, /scope must include 'atproto'/
    )
  end

  ['atproto repo:app.bsky.feed', 'atproto repo:app.bsky.feed.post?extra=true',
   'atproto Repo:app.bsky.feed.post', 'atproto transition:generic'].each do |scope|
    it "should reject undeclared scope tokens in #{scope.inspect} before discovery or session creation" do
      client.expects(:resolve_auth_server).never
      client.session_manager.expects(:create_session).never

      expect { client.authorize(pds: 'https://pds.example.com', scope: scope) }.to raise_error(
        AuthProto::Error, /not declared in client metadata/
      )
    end
  end

  ['atproto', 'atproto repo:app.bsky.feed.post',
   'rpc:app.bsky.feed.getTimeline?aud=* atproto repo:app.bsky.feed.post'].each do |scope|
    it "should accept declared scope subsets in any order: #{scope}" do
      client.send(:validate_auth_params, nil, 'https://pds.example.com', scope)
    end
  end

  it "should check scopes against the virtual metadata of a localhost client" do
    localhost = described_class.new(client_id: 'http://localhost/', redirect_uri: 'http://127.0.0.1/')

    expect {
      localhost.authorize(pds: 'https://pds.example.com', scope: 'atproto repo:app.bsky.feed.post')
    }.to raise_error(AuthProto::Error, /not declared in client metadata/)
  end
end
