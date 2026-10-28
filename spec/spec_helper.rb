# frozen_string_literal: true

require 'base64'
require 'rspec'
require 'webmock/rspec'

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require 'authproto'

# Set a consistent encryption key to use across all specs.
ENV["ATPROTO_MASTER_KEY"] = Base64.strict_encode64("0" * 32)

RSpec.configure do |config|
  config.expect_with(:rspec) do |expectations|
    expectations.syntax = %i[should expect]
  end

  config.mock_with :mocha
end

RSpec::Matchers.define :be_encrypted do
  match do |value|
    value.is_a?(Hash) &&
      value["version"] == AuthProto::Encryption::Service::VERSION &&
      value["iv"] && value["data"] && value["tag"]
  end

  failure_message { |value| "expected #{value.inspect} to contain an encrypted value with version, IV, data and tag" }
end
