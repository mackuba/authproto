# frozen_string_literal: true

require_relative 'lib/authproto/version'

Gem::Specification.new do |spec|
  spec.name = "authproto"
  spec.version = AuthProto::VERSION
  spec.authors = ["Josh Huckabee", "Kuba Suder"]
  spec.email = ["jakub.suder@gmail.com"]

  spec.summary = "Ruby implementation of an AT Protocol specific OAuth client"
  spec.description = %(
    A Ruby gem implementing an OAuth 2.1 client specifically targeted for use in AT Protocol context. Supports both
    public and confidential clients, handles DPoP, nonce management, client and server metadata JSON, PAR, PKCE,
    client assertions for confidential clients, storage of session state, and at rest encryption of stored tokens.
    Includes SQLite, Redis and in-memory storage backends, and an adapter for using the Minisky gem with OAuth
    login support.

    This gem deliberately does not support any features, profiles and configurations of OAuth that are not currently
    used in ATProto, and does not support turning off any additional requirements and restrictions that ATProto
    introduces on top of standard OAuth specifications.
  )

  spec.homepage = "https://tangled.org/mackuba.eu/authproto"

  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3"

  spec.metadata = {
    "bug_tracker_uri"   => "https://tangled.org/mackuba.eu/authproto/issues",
    "changelog_uri"     => "https://tangled.org/mackuba.eu/authproto/blob/master/CHANGELOG.md",
    "source_code_uri"   => "https://tangled.org/mackuba.eu/authproto",
    "rubygems_mfa_required" => "true"
  }

  git_files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true)
  end

  included_files = Dir.chdir(__dir__) do
    Dir['*.md'] + Dir['*.txt'] + Dir['examples/**/*'] + Dir['lib/**/*'] + Dir['sig/**/*'] - ['AGENTS.md']
  end

  spec.files = git_files & included_files

  spec.require_paths = ["lib"]

  spec.add_dependency "jose", "~> 1.2"
  spec.add_dependency "jwt", "~> 3.3"
  spec.add_dependency "didkit", "~> 0.5.0"
end
