# frozen_string_literal: true

describe AuthProto::Token::Response do
  let(:current_tokens) do
    AuthProto::State::TokenSet.new(
      access_token: 'existing-access', refresh_token: 'existing', token_type: 'DPoP',
      expires_in: 3600, scope: 'atproto', sub: 'did:plc:alice'
    )
  end
  let(:data) do
    {
      'access_token' => 'access', 'token_type' => 'DPoP', 'expires_in' => 3600,
      'refresh_token' => 'refresh', 'scope' => 'atproto transition:email', 'sub' => 'did:plc:alice'
    }
  end
  let(:response) do
    { status: 200, headers: { 'Content-Type' => 'application/json' }, body: data.to_json }
  end

  it "should return a token set with the granted permissions and expiry" do
    now = Time.now
    Time.stubs(:now).returns(now)
    tokens = described_class.parse(response)

    tokens.access_token.should == 'access'
    tokens.refresh_token.should == 'refresh'
    tokens.scope.should == data['scope']
    tokens.sub.should == data['sub']
    tokens.expires_at.should == now + 3600
  end

  it "should accept case-insensitive JSON content types with parameters" do
    response[:headers] = { 'content-TYPE' => 'Application/JSON; charset=utf-8' }
    described_class.parse(response).access_token.should == 'access'
  end

  it "should accept an omitted refresh token" do
    data.delete('refresh_token')
    described_class.parse(response).refresh_token.should be_nil
  end

  it "should prefer an issued refresh token over the fallback" do
    described_class.parse(response, current_tokens: current_tokens).refresh_token.should == 'refresh'
  end

  it "should use the fallback refresh token when the field is omitted" do
    data.delete('refresh_token')
    described_class.parse(response, current_tokens: current_tokens).refresh_token.should == 'existing'
  end

  it "should reject an explicit null refresh token even when a fallback is supplied" do
    data['refresh_token'] = nil

    expect { described_class.parse(response, current_tokens: current_tokens) }
      .to raise_error(described_class::Error, /refresh_token/)
  end

  %w[dpop DPOP dPoP].each do |type|
    it "should accept and canonicalize token type #{type}" do
      data['token_type'] = type
      described_class.parse(response).token_type.should == 'DPoP'
    end
  end

  [nil, '', 'header.payload.signature', false, 123, [], {}].each do |value|
    it "should reject a present id_token with value #{value.inspect}" do
      data['id_token'] = value

      expect { described_class.parse(response) }.to raise_error(described_class::Error, /must not include id_token/)
    end
  end

  it "should continue to ignore unrelated extension fields" do
    data['extension_field'] = 'value'
    described_class.parse(response).access_token.should == 'access'
  end

  [nil, '', 'text/html', 'application/problem+json'].each do |type|
    it "should reject content type #{type.inspect}" do
      response[:headers] = type.nil? ? {} : { 'Content-Type' => type }
      expect { described_class.parse(response) }.to raise_error(described_class::Error, /Content-Type/)
    end
  end

  [nil, '', 'invalid json', '[]', 'null', 'true', '123', '"string"'].each do |body|
    it "should reject a missing, malformed or non-object body #{body.inspect}" do
      response[:body] = body
      expect { described_class.parse(response) }.to raise_error(described_class::Error)
    end
  end

  %w[access_token token_type expires_in scope sub].each do |field|
    it "should reject a missing #{field}" do
      data.delete(field)
      expect { described_class.parse(response) }.to raise_error(described_class::Error, /Missing #{field}/)
    end
  end

  %w[access_token token_type scope sub refresh_token].each do |field|
    [nil, '', 123, false, [], {}].each do |value|
      it "should reject #{field} with value #{value.inspect}" do
        data[field] = value
        expect { described_class.parse(response) }.to raise_error(described_class::Error, /#{field}/)
      end
    end
  end

  [nil, 0, -1, 1.5, '3600', false].each do |value|
    it "should reject a non-positive or non-integer lifetime #{value.inspect}" do
      data['expires_in'] = value
      expect { described_class.parse(response) }.to raise_error(described_class::Error, /expires_in/)
    end
  end

  it "should reject bearer tokens" do
    data['token_type'] = 'Bearer'
    expect { described_class.parse(response) }.to raise_error(described_class::Error, /token_type/)
  end

  it "should require the exact atproto scope token" do
    data['scope'] = 'atproto:other transition:email'
    expect { described_class.parse(response) }.to raise_error(described_class::Error, /Invalid scope/)
  end
end
