# frozen_string_literal: true

require 'socket'
require 'timeout'
require 'uri'

require 'atproto_auth/localhost_server'

describe AuthProto::LocalhostServer do
  before do
    @previous_configuration = AuthProto.configuration
    AuthProto.reset_configuration
    AuthProto::LocalhostServer.any_instance.stubs(:puts)
  end

  after do
    AuthProto.configuration = @previous_configuration
  end

  # Use a pre-bound ephemeral listener so the test knows the port without a
  # close/rebind race. The actual HTTP exchange still uses real TCP sockets.
  def with_server(callback:, path: "/callback", timeout: 2)
    listener = TCPServer.new("127.0.0.1", 0)
    port = listener.addr[1]
    metadata = { "redirect_uris" => ["http://127.0.0.1:#{port}#{path}"] }
    TCPServer.stubs(:new).with("127.0.0.1", port).returns(listener)
    worker = Thread.new do
      [:ok, AuthProto::LocalhostServer.start(metadata, timeout: timeout, &callback)]
    rescue Exception => e # Also capture Interrupt so the test can inspect cleanup.
      [:error, e]
    end
    yield port, worker, listener
  ensure
    listener&.close unless listener&.closed?
    worker&.kill
    worker&.join
  end

  def request(port, target, method: "GET")
    Timeout.timeout(3) do
      TCPSocket.open("127.0.0.1", port) do |socket|
        socket.write("#{method} #{target} HTTP/1.1\r\nHost: 127.0.0.1:#{port}\r\nConnection: close\r\n\r\n")
        socket.read
      end
    end
  end

  def callback_target(path = "/callback", **extra)
    params = { code: "code + punctuation", state: "random-state", iss: "https://auth.example.com" }.merge(extra)
    "#{path}?#{URI.encode_www_form(params)}"
  end

  it "should yield decoded keyword-compatible parameters, return the block result and shut down" do
    received = nil
    callback = lambda do |params|
      received = params
      :authenticated
    end
    with_server(callback: callback) do |port, worker, listener|
      response = request(port, callback_target(extra: "ignored"))
      response.should include("HTTP/1.1 200 OK")
      response.should include("Authentication complete")
      response.should_not include("random-state")
      worker.value.should == [:ok, :authenticated]
      received.should == { code: "code + punctuation", state: "random-state", iss: "https://auth.example.com" }
      listener.closed?.should be true
    end
  end

  [nil, false].each do |result|
    it "should shut down when the callback returns #{result.inspect}" do
      with_server(callback: ->(_params) { result }) do |port, worker, listener|
        request(port, callback_target).should include("200 OK")
        worker.value.should == [:ok, result]
        listener.closed?.should be true
      end
    end
  end

  it "should use the callback path from metadata and ignore unrelated requests" do
    calls = 0
    with_server(path: "/oauth/done", callback: ->(_params) { calls += 1 }) do |port, worker, _listener|
      request(port, "/favicon.ico").should include("404 Not Found")
      request(port, callback_target).should include("404 Not Found")
      request(port, "/oauth/done", method: "POST").should include("405 Method Not Allowed")
      calls.should == 0
      request(port, callback_target("/oauth/done")).should include("200 OK")
      worker.value.should == [:ok, 1]
    end
  end

  it "should keep listening after incomplete or duplicate callback parameters" do
    with_server(callback: ->(_params) { :ok }) do |port, worker, _listener|
      request(port, "/callback?code=missing-state-and-issuer").should include("400 Bad Request")
      request(port, "#{callback_target}&code=duplicate").should include("400 Bad Request")
      request(port, callback_target).should include("200 OK")
      worker.value.should == [:ok, :ok]
    end
  end

  it "should report an OAuth rejection in the browser and raise it in the caller" do
    with_server(callback: ->(_params) { raise RSpec::Expectations::ExpectationNotMetError, "Rejected authorization must not invoke the callback" }) do |port, worker, listener|
      query = URI.encode_www_form(error: "access_denied", error_description: "User declined")
      request(port, "/callback?#{query}").should include("Authentication failed")
      status, error = worker.value
      status.should == :error
      error.should be_an_instance_of(AuthProto::LocalhostServer::CallbackError)
      error.error_code.should == "access_denied"
      error.error_description.should == "User declined"
      listener.closed?.should be true
    end
  end

  it "should propagate exceptions from handle_callback after responding and closing the listener" do
    failure = ArgumentError.new("issuer mismatch")
    with_server(callback: ->(_params) { raise failure }) do |port, worker, listener|
      request(port, callback_target).should include("400 Bad Request")
      worker.value.should == [:error, failure]
      listener.closed?.should be true
    end
  end

  it "should not swallow a timeout raised by the callback block" do
    failure = Timeout::Error.new("token exchange timed out")
    with_server(callback: ->(_params) { raise failure }) do |port, worker, listener|
      request(port, callback_target).should include("400 Bad Request")
      worker.value.should == [:error, failure]
      listener.closed?.should be true
    end
  end

  it "should close the server when interrupted" do
    with_server(callback: ->(_params) { raise Interrupt }) do |port, worker, listener|
      request(port, callback_target)
      status, error = worker.value
      status.should == :error
      error.should be_an_instance_of(Interrupt)
      listener.closed?.should be true
    end
  end

  it "should time out and close the server if no callback arrives" do
    with_server(timeout: 0.02, callback: ->(_params) { raise RSpec::Expectations::ExpectationNotMetError, "Unexpected callback" }) do |_port, worker, listener|
      status, error = worker.value
      status.should == :error
      error.should be_an_instance_of(Timeout::Error)
      listener.closed?.should be true
    end
  end

  it "should reject missing metadata and non-loopback, HTTPS or invalid redirect URIs" do
    [{}, { redirect_uris: [] }].each do |metadata|
      expect { AuthProto::LocalhostServer.new(metadata) }.to raise_error(ArgumentError)
    end
    %w[https://127.0.0.1:9292/callback http://example.com:9292/callback http://0.0.0.0:9292/callback
       http://192.168.1.1:9292/callback http://127.0.0.1:0/callback http://user@localhost:9292/callback
       http://localhost:9292/callback#fragment].each do |url|
      expect { AuthProto::LocalhostServer.new("redirect_uris" => [url]) }.to raise_error(ArgumentError)
    end
  end

  it "should require a block and positive timeout without changing global configuration" do
    metadata = { "redirect_uris" => ["http://127.0.0.1:9292/callback"] }
    previous_http = AuthProto.configuration.http_client
    expect { AuthProto::LocalhostServer.start(metadata) }.to raise_error(ArgumentError)
    expect { AuthProto::LocalhostServer.start(metadata, timeout: 0) {} }.to raise_error(ArgumentError)
    AuthProto.configuration.http_client.should equal(previous_http)
  end
end
