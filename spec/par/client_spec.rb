# frozen_string_literal: true

describe AuthProto::PAR::Client do
  before do
    @par_endpoint = "https://auth.example.com/par"
    @dpop_client = mock("dpop_client")
    @nonce_manager = mock("nonce_manager")
    @dpop_client.stubs(:nonce_manager).returns(@nonce_manager)
    @client = AuthProto::PAR::Client.new(par_endpoint: @par_endpoint, dpop_client: @dpop_client)
  end

  describe "#initialize" do
    it "should raise an error if endpoint is not HTTPS" do
      expect {
        AuthProto::PAR::Client.new(par_endpoint: "http://auth.example.com/par", dpop_client: @dpop_client)
      }.to raise_error(AuthProto::PAR::Error)
    end

    it "should initialize correctly with a valid HTTPS endpoint" do
      @client.par_endpoint.should == @par_endpoint
      @client.dpop_client.should == @dpop_client
    end
  end

  describe "#submit" do
    before do
      @request = mock("request")
      @request.stubs(:is_a?).with(AuthProto::PAR::Request).returns(true)

      @proof = "mocked_dpop_proof"
      @response = { status: 201, headers: { 'content-type' => 'application/json' },
                    body: '{"request_uri":"mocked_uri","expires_in":3600}' }
      @server_origin = "https://auth.example.com"

      @request.stubs(:to_form).returns("client_id=mock_client_id&scope=mock_scope")
      @dpop_client.stubs(:generate_proof).returns(@proof)
      @nonce_manager.stubs(:get).returns("mocked_nonce")
      @http_client = mock("http_client")
      @http_client.stubs(:get)
      @http_client.stubs(:post).returns(@response)
      AuthProto.configure do |configuration|
        configuration.http_client = @http_client
      end
    end

    it "should submit the PAR request and return a Response object on success" do
      response = @client.submit(@request)
      response.should be_an_instance_of(AuthProto::PAR::Response)
      response.request_uri.should == "mocked_uri"
      response.expires_in.should == 3600
    end

    it "should accept case-insensitive JSON content types and header names with parameters" do
      @response[:headers] = { 'CoNtEnT-TyPe' => 'Application/JSON; charset=utf-8' }

      @client.submit(@request).expires_in.should == 3600
    end

    [nil, '', 'text/plain', 'application/jsonp', 'application/problem+json'].each do |content_type|
      it "should reject a non-JSON or missing content type: #{content_type.inspect}" do
        @response[:headers] = content_type ? { 'content-type' => content_type } : nil

        expect { @client.submit(@request) }.to raise_error(AuthProto::PAR::Error, /must use application\/json/)
      end
    end

    ['[]', 'null', 'true', '90', '"string"'].each do |body|
      it "should reject a JSON body that is not an object: #{body}" do
        @response[:body] = body

        expect { @client.submit(@request) }.to raise_error(AuthProto::PAR::Error, /must be a JSON object/)
      end
    end

    it "should reject malformed JSON" do
      @response[:body] = '{'

      expect { @client.submit(@request) }.to raise_error(AuthProto::PAR::Error, /invalid JSON response/)
    end

    [{}, { request_uri: [], expires_in: 90 }, { request_uri: '', expires_in: 90 },
     { request_uri: 'uri', expires_in: '90' }, { request_uri: 'uri', expires_in: 1.5 },
     { request_uri: 'uri', expires_in: 0 }, { request_uri: 'uri' }].each do |data|
      it "should reject invalid response fields: #{data.inspect}" do
        @response[:body] = data.to_json

        expect { @client.submit(@request) }.to raise_error(AuthProto::PAR::Error, /must be/)
      end
    end

    it "should retry the request with a nonce if the response indicates 'use_dpop_nonce'" do
      error_response = { status: 400, body: '{"error":"use_dpop_nonce"}', headers: { "DPoP-Nonce" => "new_nonce" } }
      @nonce_manager.expects(:update).with(nonce: "new_nonce", server_url: @server_origin)
      AuthProto.configuration.http_client.stubs(:post).returns(error_response).then.returns(@response)

      response = @client.submit(@request)
      response.should be_an_instance_of(AuthProto::PAR::Response)
    end

    it "should raise an error if the response is invalid" do
      AuthProto.configuration.http_client.stubs(:post).returns({ status: 400, body: '{"error":"invalid_request"}' })
      expect { @client.submit(@request) }.to raise_error(AuthProto::PAR::Error)
    end

    it "should raise an error if the argument is not a PAR request" do
      request = Net::HTTP::Get.new('/')

      expect { @client.submit(request) }.to raise_error(AuthProto::PAR::Error, /Expected a PAR::Request/)
    end
  end

  describe "#build_authorization_url" do
    it "should construct a valid authorization URL" do
      authorization_endpoint = "https://auth.example.com/authorize"
      request_uri = "mocked_request_uri"
      client_id = "mocked_client_id"

      url = @client.build_authorization_url(authorization_endpoint: authorization_endpoint,
                                            request_uri: request_uri,
                                            client_id: client_id)
      expected_url = "https://auth.example.com/authorize?request_uri=mocked_request_uri&client_id=mocked_client_id"
      url.should == expected_url
    end

    it "should escape asterisks for terminal links while preserving the exact localhost client ID" do
      client_id = 'http://localhost/?' + URI.encode_www_form(
        redirect_uri: 'http://127.0.0.1:9292/callback',
        scope: 'atproto repo:app.bsky.feed.post rpc:app.bsky.feed.getTimeline?aud=*'
      )
      request_uri = 'urn:ietf:params:oauth:request_uri:test'

      url = @client.build_authorization_url(
        authorization_endpoint: 'https://auth.example.com/authorize',
        request_uri: request_uri,
        client_id: client_id
      )

      url.should end_with('%2A')
      url.should_not include('*')
      URI.decode_www_form(URI(url).query).to_h.should == {
        'request_uri' => request_uri,
        'client_id' => client_id
      }
    end
  end
end
