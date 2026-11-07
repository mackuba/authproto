# frozen_string_literal: true

describe AuthProto::Client, '.localhost_app?' do
  ['http://localhost', 'http://localhost/', 'http://localhost/?scope=atproto',
   'http://localhost?scope=atproto', 'HTTP://LOCALHOST/'].each do |client_id|
    it "should recognize the localhost client ID #{client_id}" do
      described_class.localhost_app?(client_id).should be true
    end
  end

  [nil, '', 123, 'localhost', 'https://localhost/', 'http://127.0.0.1/',
   'http://localhost.example.com/', 'http://localhost@evil.example/', 'http://localhost:3000/',
   "prefix\nhttp://localhost/"].each do |client_id|
    it "should reject a different client ID #{client_id.inspect}" do
      described_class.localhost_app?(client_id).should be false
    end
  end
end
