# frozen_string_literal: true

describe AuthProto::ValidatedURI do
  it 'accepts HTTP and HTTPS with a host' do
    %w[http https].each do |scheme|
      parsed = described_class.new("#{scheme}://example.com")
      expect(parsed.scheme).to eq(scheme)
      expect(parsed.host).to eq('example.com')
    end
  end

  [nil, 123, '', '/relative', 'not a url', 'ftp://example.com', 'file:///tmp/file',
   'mailto:user@example.com', 'https:page', 'https://', 'https:///path',
   'https://bad host', 'https://example.com:bad'].each do |url|
    it "raises URI::InvalidURIError for #{url.inspect}" do
      expect { described_class.new(url) }.to raise_error(URI::InvalidURIError)
    end
  end

  it 'preserves explicit ports as strings, including default and empty ports' do
    { 'https://example.com' => nil, 'https://example.com:443' => '443',
      'http://example.com:80' => '80', 'https://example.com:8443' => '8443',
      'https://example.com:0443' => '0443', 'https://example.com:' => '' }.each do |url, port|
      expect(described_class.new(url).port).to eq(port)
    end
  end

  it 'preserves absent, empty, and populated userinfo' do
    { 'https://example.com' => nil, 'https://@example.com' => '',
      'https://user@example.com' => 'user', 'https://user:pass@example.com' => 'user:pass',
      'https://user%40name:p%3Ass@example.com' => 'user%40name:p%3Ass' }.each do |url, userinfo|
      expect(described_class.new(url).userinfo).to eq(userinfo)
    end
  end

  describe 'port accessors' do
    {
      'https://example.com' => [nil, 443],
      'http://example.com' => [nil, 80],
      'https://example.com:443' => ['443', 443],
      'http://example.com:80' => ['80', 80],
      'https://example.com:8443' => ['8443', 8443],
      'http://example.com:9292' => ['9292', 9292],
      'https://example.com:0443' => ['0443', 443],
      'https://example.com:' => ['', 443],
      'http://example.com:' => ['', 80]
    }.each do |url, (specified, effective)|
      it "distinguishes the specified and effective port for #{url}" do
        parsed = described_class.new(url)

        expect(parsed.specified_port).to eq(specified)
        expect(parsed.effective_port).to eq(effective)
      end
    end
  end

  it 'normalizes only the root path to an empty string' do
    { '' => '', '/' => '', '/path' => '/path', '/path/' => '/path/', '//' => '//' }.each do |path, expected|
      expect(described_class.new("https://example.com#{path}").path).to eq(expected)
    end
  end

  it 'delegates the other URI readers and string conversion' do
    url = 'https://user:pass@[::1]:8443/path?query=value#fragment'
    parsed = described_class.new(url)
    uri = URI(url)

    %i[scheme host hostname query fragment user password registry opaque default_port
       request_uri origin absolute? relative? hierarchical? to_s to_str].each do |field|
      expect(parsed.public_send(field)).to eq(uri.public_send(field))
    end

    expect(parsed.to_uri).to be_a(URI::HTTPS)
  end

  it 'accepts URI objects without modifying them' do
    uri = URI('http://localhost:9292/')
    parsed = described_class.new(uri)
    expect(parsed.host).to eq('localhost')
    expect(parsed.port).to eq('9292')
    expect(parsed.path).to eq('')
    expect(uri.path).to eq('/')
  end
end
