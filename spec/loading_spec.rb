# frozen_string_literal: true

require 'open3'
require 'rbconfig'

describe "Library loading" do
  lib_dir = File.expand_path('../lib', __dir__)

  it "should expose public entry points while leaving optional integrations unloaded" do
    _, stderr, status = Open3.capture3(RbConfig.ruby, '-I', lib_dir, '-e', <<~RUBY)
      require 'authproto'

      [AuthProto::VERSION, AuthProto::Client, AuthProto::Configuration,
       AuthProto::HTTPClient, AuthProto::InsecureHTTPClient, AuthProto::LocalhostServer,
       AuthProto::Serialization::DPoPKey]

      abort "Redis adapter eagerly loaded" unless AuthProto::Storage.autoload?(:Redis)
      abort "SQLite adapter eagerly loaded" unless AuthProto::Storage.autoload?(:SQLite)
      abort "Minisky eagerly loaded" if defined?(Minisky)

      AuthProto.configuration.validate
    RUBY

    expect(status.success?).to be(true), stderr
  end
end
