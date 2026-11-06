# frozen_string_literal: true

describe AuthProto::Client, '#http' do
  it "should use the current global HTTP client after configuration is replaced" do
    client = described_class.new(client_id: 'http://localhost', redirect_uri: 'http://127.0.0.1/')
    configuration = AuthProto::Configuration.new
    AuthProto.stubs(:configuration).returns(configuration)
    transport = AuthProto::HTTPClient.new
    configuration.http_client = transport

    client.http.should equal(transport)

    replacement = AuthProto::Configuration.new
    AuthProto.stubs(:configuration).returns(replacement)
    client.http.should be_nil

    replacement.http_client = AuthProto::InsecureHTTPClient.new
    client.http.should equal(replacement.http_client)
  end
end
