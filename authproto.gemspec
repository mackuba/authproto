# frozen_string_literal: true

require_relative 'lib/authproto/version'

Gem::Specification.new do |spec|
  spec.name = "authproto"
  spec.version = AuthProto::VERSION
  spec.authors = ["Josh Huckabee", "Kuba Suder"]

  spec.summary = "Ruby implementation of the AT Protocol OAuth specification"
  spec.description = "A Ruby library for implementing AT Protocol OAuth flows, including DPoP, PAR, and dynamic client registration. Supports both client and server-side implementations with comprehensive security features."
  spec.homepage = "https://github.com/mackuba/authproto"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/mackuba/authproto"
  spec.metadata["changelog_uri"] = "https://github.com/mackuba/authproto/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "jose", "~> 1.2"
  spec.add_dependency "jwt", "~> 3.3"
  spec.add_dependency "didkit", "~> 0.5.0"
end
