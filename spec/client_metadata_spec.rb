# frozen_string_literal: true

require 'json'

describe AuthProto::ClientMetadata do
  before do
    @valid_metadata = {
      "client_id" => "https://example.com/metadata.json",
      "grant_types" => %w[authorization_code refresh_token],
      "response_types" => ["code"],
      "redirect_uris" => ["https://example.com/callback"],
      "scope" => "atproto offline_access",
      "token_endpoint_auth_method" => "none",
      "dpop_bound_access_tokens" => true,
      "client_name" => "Example Client",
      "application_type" => "web"
    }
  end

  describe "initialization" do
    it "should initialize with valid metadata" do
      client_metadata = AuthProto::ClientMetadata.new(@valid_metadata)
      client_metadata.client_id.should == "https://example.com/metadata.json"
      client_metadata.grant_types.should == %w[authorization_code refresh_token]
      client_metadata.response_types.should == ["code"]
      client_metadata.redirect_uris.should == ["https://example.com/callback"]
      client_metadata.scope.should == "atproto offline_access"
      client_metadata.client_name.should == "Example Client"
      client_metadata.application_type.should == "web"
    end

    it "should initialize with localhost client_id" do
      @valid_metadata["client_id"] = "http://localhost"
      @valid_metadata["application_type"] = "native"
      @valid_metadata["redirect_uris"] = ["http://127.0.0.1:9292/callback"]
      client_metadata = AuthProto::ClientMetadata.new(@valid_metadata)
      client_metadata.client_id.should == "http://localhost"
    end

    it "should raise an error when client_id is missing" do
      @valid_metadata.delete("client_id")
      expect { AuthProto::ClientMetadata.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
    end

    it "should raise an error for invalid client_id scheme" do
      @valid_metadata["client_id"] = "http://example.com"
      expect { AuthProto::ClientMetadata.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
    end

    it "should raise an error for invalid grant types" do
      @valid_metadata["grant_types"] = ["invalid_grant"]
      expect { AuthProto::ClientMetadata.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
    end

    it "should raise an error when redirect URIs are missing" do
      @valid_metadata.delete("redirect_uris")
      expect { AuthProto::ClientMetadata.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
    end

    it "should raise an error for invalid redirect URI scheme" do
      @valid_metadata["redirect_uris"] = ["http://example.com/callback"]
      expect { AuthProto::ClientMetadata.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
    end

    it "should raise an error for invalid scope" do
      @valid_metadata["scope"] = "invalid_scope"
      expect { AuthProto::ClientMetadata.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
    end

    it "should raise an error for missing dpop_bound_access_tokens" do
      @valid_metadata.delete("dpop_bound_access_tokens")
      expect { AuthProto::ClientMetadata.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
    end
  end

  describe "metadata shape and application type" do
    [nil, false, [], "metadata", 42].each do |metadata|
      it "should reject non-object metadata #{metadata.inspect}" do
        expect { described_class.new(metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /must be a hash/)
      end
    end

    it "should default an omitted application_type to web before checking redirects" do
      @valid_metadata.delete("application_type")
      described_class.new(@valid_metadata).application_type.should == "web"
    end

    [false, "", "browser"].each do |type|
      it "should reject an invalid application_type #{type.inspect}" do
        @valid_metadata["application_type"] = type
        expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /application_type/)
      end
    end

    it "should accept a native application's IPv6 loopback redirect" do
      @valid_metadata.merge!("application_type" => "native", "redirect_uris" => ["http://[::1]:9292/callback"])
      described_class.new(@valid_metadata).application_type.should == "native"
    end
  end

  describe "client ID validation" do
    ["https://example.com/metadata.json", "https://example.com/metadata.json?version=2"].each do |client_id|
      it "should accept an allowed HTTPS client ID #{client_id}" do
        @valid_metadata["client_id"] = client_id
        described_class.new(@valid_metadata).client_id.should == client_id
      end
    end

    ["http://localhost", "http://localhost/", "http://localhost?scope=atproto",
     "http://localhost/?scope=atproto&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback"].each do |client_id|
      it "should accept an allowed localhost client ID #{client_id}" do
        @valid_metadata.merge!("client_id" => client_id, "application_type" => "native",
                               "redirect_uris" => ["http://127.0.0.1:9292/callback"])
        described_class.new(@valid_metadata).client_id.should == client_id
      end
    end

    ["not a URI", "https:metadata.json", "https:/metadata.json", "https://",
     "https://example.com:443/metadata.json", "https://example.com:8443/metadata.json", "https://example.com:/metadata.json",
     "https://user:pass@example.com/metadata.json", "https://@example.com/metadata.json",
     "https://example.com/metadata.json#section", "https://example.com/metadata.json#",
     "http://localhost:80", "http://localhost:9292/", "http://localhost:/", "http://localhost/path", "http://localhost//",
     "http://user@localhost/", "http://@localhost/", "http://localhost/#", "http://localhost.evil.example/", "http://127.0.0.1/", "http://[::1]/"].each do |client_id|
      it "should reject invalid client ID #{client_id.inspect}" do
        @valid_metadata["client_id"] = client_id
        expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /client_id/)
      end
    end

    [123, [], {}].each do |client_id|
      it "should reject a non-string client ID #{client_id.inspect}" do
        @valid_metadata["client_id"] = client_id
        expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /must be a string/)
      end
    end
  end

  describe "redirect URI validation" do
    describe "web clients" do
      ["https://example.com/callback", "https://login.example.net/callback",
       "https://login.example.net:8443/callback", "https://example.com/callback?flow=login"].each do |redirect_uri|
        it "should accept HTTPS callback #{redirect_uri}" do
          @valid_metadata["redirect_uris"] = [redirect_uri]
          described_class.new(@valid_metadata).redirect_uris.should == [redirect_uri]
        end
      end

      ["http://example.com/callback", "http://127.0.0.1:9292/callback", "http://[::1]:9292/callback",
       "ftp://127.0.0.1/callback", "com.example:/callback", "/callback", "//example.com/callback",
       "https:/callback", "https:callback", "not a URI"].each do |redirect_uri|
        it "should reject a non-HTTPS or non-absolute callback #{redirect_uri.inspect}" do
          @valid_metadata["redirect_uris"] = [redirect_uri]
          expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
        end
      end

      it "should not exempt localhost web clients from HTTPS callback requirements" do
        @valid_metadata.merge!("client_id" => "http://localhost", "redirect_uris" => ["http://127.0.0.1:9292/callback"])
        expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /HTTPS/)
      end
    end

    describe "native clients" do
      before { @valid_metadata["application_type"] = "native" }

      ["https://example.com/callback", "https://EXAMPLE.COM/callback?flow=login",
       "http://127.0.0.1/callback", "http://127.0.0.1:9292/callback",
       "http://[::1]/callback", "http://[::1]:9292/callback?flow=login",
       "com.example:/", "com.example:/callback", "com.example:/oauth/callback",
       "com.example:/callback?flow=login"].each do |redirect_uri|
        it "should accept callback #{redirect_uri}" do
          @valid_metadata["redirect_uris"] = [redirect_uri]
          described_class.new(@valid_metadata).redirect_uris.should == [redirect_uri]
        end
      end

      ["https://other.example/callback", "https://example.com:8443/callback"].each do |redirect_uri|
        it "should reject an HTTPS callback with a different origin #{redirect_uri}" do
          @valid_metadata["redirect_uris"] = [redirect_uri]
          expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /match client_id origin/)
        end
      end

      ["http://localhost:9292/callback", "http://example.com/callback", "http://192.168.1.1/callback",
       "http://127.0.0.2/callback", "ftp://127.0.0.1/callback"].each do |redirect_uri|
        it "should reject a callback outside the HTTP loopback exception #{redirect_uri}" do
          @valid_metadata["redirect_uris"] = [redirect_uri]
          expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
        end
      end

      ["net.example:/callback", "com.example:callback", "com.example://other.example/",
       "com.example:///callback", "com.example:////callback", "/callback"].each do |redirect_uri|
        it "should reject an invalid custom scheme or path #{redirect_uri.inspect}" do
          @valid_metadata["redirect_uris"] = [redirect_uri]
          expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata)
        end
      end

      it "should match a reverse-domain scheme against a case-insensitive client hostname" do
        @valid_metadata.merge!("client_id" => "https://EXAMPLE.COM/metadata.json", "redirect_uris" => ["com.example:/callback"])
        described_class.new(@valid_metadata).redirect_uris.should == ["com.example:/callback"]
      end

      it "should reject a custom scheme without a reverse-domain namespace" do
        @valid_metadata.merge!("client_id" => "http://localhost", "redirect_uris" => ["localhost:/callback"])
        expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /reversed client_id domain/)
      end

      ["http://user@127.0.0.1:9292/callback", "http://[::1]:9292/callback#fragment",
       "com.example:/callback#fragment"].each do |redirect_uri|
        it "should reject credentials or fragments in a native callback #{redirect_uri}" do
          @valid_metadata["redirect_uris"] = [redirect_uri]
          expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /credentials|fragment/)
        end
      end
    end

    %w[web native].each do |application_type|
      describe "common checks for #{application_type} clients" do
        before { @valid_metadata["application_type"] = application_type }

        ["https://user:pass@example.com/callback", "https://@example.com/callback",
         "https://example.com/callback#fragment", "https://example.com/callback#"].each do |redirect_uri|
          it "should reject credentials or fragments in #{redirect_uri}" do
            @valid_metadata["redirect_uris"] = [redirect_uri]
            expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /credentials|fragment/)
          end
        end

        ["https://example.com:443/callback", "https://example.com:0443/callback",
         "https://example.com:/callback"].each do |redirect_uri|
          it "should reject an explicitly supplied default HTTPS port #{redirect_uri}" do
            @valid_metadata["redirect_uris"] = [redirect_uri]
            expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /default port/)
          end
        end
      end
    end
  end

  describe "required field validation" do
    %w[grant_types response_types redirect_uris].each do |field|
      ["authorization_code", {}, 42].each do |value|
        it "should reject a non-array #{field}: #{value.inspect}" do
          @valid_metadata[field] = value
          expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /must be an array/)
        end
      end
    end

    [[], ["refresh_token"], ["authorization_code", "password"]].each do |grants|
      it "should reject invalid grant types #{grants.inspect}" do
        @valid_metadata["grant_types"] = grants
        expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /grant type|authorization_code/)
      end
    end

    it "should allow refresh tokens without an offline_access scope" do
      described_class.new(@valid_metadata).grant_types.should include("refresh_token")
    end

    it "should allow authorization_code without refresh_token" do
      @valid_metadata["grant_types"] = ["authorization_code"]
      described_class.new(@valid_metadata).grant_types.should == ["authorization_code"]
    end

    it "should reject an empty redirect URI list" do
      @valid_metadata["redirect_uris"] = []
      expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /must not be empty/)
    end

    it "should reject non-string redirect URI entries" do
      @valid_metadata["redirect_uris"] = [123]
      expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /entries must be strings/)
    end

    it "should reject a non-string scope" do
      @valid_metadata["scope"] = ["atproto"]
      expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /scope must be a string/)
    end

    [false, "true", 1].each do |value|
      it "should require boolean true for dpop_bound_access_tokens: #{value.inspect}" do
        @valid_metadata["dpop_bound_access_tokens"] = value
        expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /must be true/)
      end
    end
  end

  describe "scope and response-type syntax" do
    ["atproto transition:generic", "atproto repo:app.bsky.feed.post?action=create",
     "atproto include:app.example.permissions?aud=did:web:api.example.com%23bsky_appview",
     "atproto extension:future"].each do |scope|
      it "should accept valid scope syntax #{scope.inspect}" do
        @valid_metadata["scope"] = scope
        described_class.new(@valid_metadata).scope.should == scope
      end
    end

    ["", " atproto", "atproto ", "atproto  transition:generic", "atproto\ttransition:generic",
     "atproto\n", "atproto\r\ntransition:generic", "atproto café", 'atproto invalid"scope',
     'atproto invalid\\scope', "atproto\u0000"].each do |scope|
      it "should reject malformed scope syntax #{scope.inspect}" do
        @valid_metadata["scope"] = scope
        expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /valid tokens/)
      end
    end

    ["atproto atproto", "atproto transition:generic transition:generic"].each do |scope|
      it "should accept and preserve duplicate scopes #{scope.inspect}" do
        @valid_metadata["scope"] = scope
        described_class.new(@valid_metadata).scope.should == scope
      end
    end

    it "should treat scope names as case-sensitive" do
      @valid_metadata["scope"] = "atproto extension:Read extension:read"
      described_class.new(@valid_metadata).scope.should == @valid_metadata["scope"]
    end

    [["authorization_code", "authorization_code"], ["authorization_code", "refresh_token", "refresh_token"]].each do |grants|
      it "should accept and preserve duplicate grant types #{grants.inspect}" do
        @valid_metadata["grant_types"] = grants
        described_class.new(@valid_metadata).grant_types.should == grants
      end
    end

    [123, nil, {}, false, []].each do |type|
      it "should reject a non-string response_types entry #{type.inspect}" do
        @valid_metadata["response_types"] = ["code", type]
        expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /only strings/)
      end
    end

    it "should accept and preserve duplicate response types" do
      @valid_metadata["response_types"] = ["code", "code"]
      described_class.new(@valid_metadata).response_types.should == ["code", "code"]
    end

    it "should require a code entry" do
      @valid_metadata["response_types"] = ["token"]
      expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /must include 'code'/)
    end

    it "should accept arbitrary response-type strings alongside the required code entry" do
      @valid_metadata["response_types"] = ["code", "unknown", "CODE", "code id_token", "code  token", "code\ttoken", ""]
      described_class.new(@valid_metadata).response_types.should == @valid_metadata["response_types"]
    end
  end

  describe "optional field validation" do
    [false, 123, []].each do |name|
      it "should reject a non-string client_name #{name.inspect}" do
        @valid_metadata["client_name"] = name
        expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /client_name must be a string/)
      end
    end

    it "should accept omitted optional display fields" do
      @valid_metadata.delete("client_name")
      metadata = described_class.new(@valid_metadata)
      metadata.client_name.should be_nil
      metadata.logo_uri.should be_nil
      metadata.tos_uri.should be_nil
      metadata.policy_uri.should be_nil
    end

    %w[logo_uri tos_uri policy_uri].each do |field|
      it "should preserve a valid #{field}" do
        @valid_metadata[field] = "https://static.example.com/page#section"
        described_class.new(@valid_metadata).public_send(field).should == @valid_metadata[field]
      end

      [false, 123, "http://example.com/page", "https:page"].each do |value|
        it "should reject an invalid #{field}: #{value.inspect}" do
          @valid_metadata[field] = value
          expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /URI must/)
        end
      end
    end

    it "should accept a client_uri with the same hostname" do
      @valid_metadata["client_uri"] = uri = 'https://example.com/home'

      described_class.new(@valid_metadata).client_uri.should == uri
    end

    ["ftp://example.com/home", "//example.com/home", "/home", ""].each do |uri|
      it "should reject a client_uri without an HTTP(S) scheme and hostname: #{uri.inspect}" do
        @valid_metadata["client_uri"] = uri

        expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /HTTP or HTTPS/)
      end
    end

    ["http:home", "https:home"].each do |uri|
      it "should reject a client_uri without a hostname: #{uri.inspect}" do
        @valid_metadata["client_uri"] = uri

        expect { described_class.new(@valid_metadata) }.to raise_error(
          AuthProto::InvalidClientMetadata, /must have the same hostname/
        )
      end
    end

    it "should reject a client_uri with a different hostname" do
      @valid_metadata["client_uri"] = "https://other.example.com/home"

      expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /same hostname/)
    end

    it "should reject a non-string client_uri" do
      @valid_metadata["client_uri"] = false
      expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /client_uri must be a string/)
    end
  end

  describe "client authentication methods" do
    it "should reject an omitted authentication method" do
      @valid_metadata.delete("token_endpoint_auth_method")
      expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /token_endpoint_auth_method is required/)
    end

    it "should reject a null authentication method" do
      @valid_metadata["token_endpoint_auth_method"] = nil
      expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /token_endpoint_auth_method is required/)
    end

    ["none"].each do |method|
      it "should accept public authentication with method #{method.inspect}" do
        @valid_metadata["token_endpoint_auth_method"] = method
        metadata = described_class.new(@valid_metadata)
        metadata.confidential?.should be false
        metadata.token_endpoint_auth_method.should == method
      end

      ["ES256", "none", "RS256", "", false, 123].each do |algorithm|
        it "should reject signing algorithm #{algorithm.inspect} for public method #{method.inspect}" do
          @valid_metadata["token_endpoint_auth_method"] = method
          @valid_metadata["token_endpoint_auth_signing_alg"] = algorithm
          expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /must be unset for public clients/)
        end
      end
    end

    ["client_secret_basic", "client_secret_post", "unknown", "", false, 123, []].each do |method|
      it "should reject unsupported authentication method #{method.inspect}" do
        @valid_metadata["token_endpoint_auth_method"] = method
        expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /unsupported token_endpoint_auth_method/)
      end
    end
  end

  describe "confidential client metadata" do
    before do
      @valid_metadata.merge!("token_endpoint_auth_method" => "private_key_jwt", "token_endpoint_auth_signing_alg" => "ES256",
                             "jwks" => { "keys" => [{ "kid" => "client-key", "use" => "sig" }] })
    end

    it "should accept an inline signing-key set" do
      metadata = described_class.new(@valid_metadata)
      metadata.confidential?.should be true
      metadata.jwks.should == @valid_metadata["jwks"]
    end

    [[], 42, { "keys" => "not an array" }, { "keys" => nil }].each do |jwks|
      it "should reject a malformed JWK set #{jwks.inspect}" do
        @valid_metadata["jwks"] = jwks
        expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /jwks/)
      end
    end

    it "should reject a non-object key entry" do
      @valid_metadata["jwks"] = { "keys" => [42] }
      expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /must be a hash/)
    end

    it "should reject a signing key without a kid" do
      @valid_metadata["jwks"]["keys"].first.delete("kid")
      expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /kid/)
    end

    it "should accept key_ops sign without use sig" do
      @valid_metadata["jwks"] = { "keys" => [{ "kid" => "client-key", "key_ops" => ["sign"] }] }
      described_class.new(@valid_metadata).confidential?.should be true
    end

    it "should reject a key not designated for signing" do
      @valid_metadata["jwks"] = { "keys" => [{ "kid" => "client-key", "key_ops" => ["verify"] }] }
      expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /use='sig'/)
    end

    it "should reject a non-array key_ops" do
      @valid_metadata["jwks"]["keys"].first["key_ops"] = "sign"
      expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /key_ops must be an array/)
    end

    it "should reject both jwks and jwks_uri" do
      @valid_metadata["jwks_uri"] = "https://example.com/jwks.json"
      expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /cannot use both/)
    end

    it "should reject missing key configuration" do
      @valid_metadata.delete("jwks")
      expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /must provide/)
    end

    it "should accept a HTTPS jwks_uri without inline keys" do
      @valid_metadata.delete("jwks")
      @valid_metadata["jwks_uri"] = "https://example.com/jwks.json"
      described_class.new(@valid_metadata).jwks_uri.should == @valid_metadata["jwks_uri"]
    end

    it "should reject an HTTP jwks_uri" do
      @valid_metadata.delete("jwks")
      @valid_metadata["jwks_uri"] = "http://example.com/jwks.json"
      expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /must use HTTPS/)
    end

    [nil, "none", "ES384"].each do |algorithm|
      it "should reject a missing or unsupported signing algorithm #{algorithm.inspect}" do
        @valid_metadata["token_endpoint_auth_signing_alg"] = algorithm
        expect { described_class.new(@valid_metadata) }.to raise_error(AuthProto::InvalidClientMetadata, /must be ES256/)
      end
    end
  end

  describe ".from_url" do
    let(:http_client) { AuthProto::HTTPClient.new }

    before do
      @previous_configuration = AuthProto.configuration
      AuthProto.reset_configuration
      AuthProto.configuration.http_client = http_client
    end

    after do
      AuthProto.configuration = @previous_configuration
    end

    it "should create an instance from valid URL metadata" do
      http_client.stubs(:get).returns(status: 200, headers: { "content-type" => "application/json" }, body: @valid_metadata.to_json)

      client_metadata = AuthProto::ClientMetadata.from_url("https://example.com/metadata.json")
      client_metadata.should be_an_instance_of(AuthProto::ClientMetadata)
      client_metadata.client_id.should == "https://example.com/metadata.json"
    end

    it "should raise an error for invalid URL scheme" do
      expect {
        AuthProto::ClientMetadata.from_url("http://example.com/metadata")
      }.to raise_error(AuthProto::InvalidClientMetadata)
    end

    it "should raise an error for client_id mismatch in metadata" do
      http_client.stubs(:get).returns(status: 200, headers: { "content-type" => "application/json" }, body: @valid_metadata.to_json)

      @valid_metadata["client_id"] = "https://otherexample.com"

      expect {
        AuthProto::ClientMetadata.from_url("https://example.com/metadata")
      }.to raise_error(AuthProto::InvalidClientMetadata)
    end
  end

  describe ".from_url localhost virtual metadata" do
    before do
      @previous_configuration = AuthProto.configuration
      AuthProto.reset_configuration
      AuthProto.configuration.http_client = mock("unused HTTP client")
      AuthProto.configuration.http_client.expects(:get).never
    end

    after { AuthProto.configuration = @previous_configuration }

    ["http://localhost", "http://localhost/", "http://localhost/?"].each do |url|
      it "should generate default localhost metadata for #{url.inspect}" do
        metadata = described_class.from_url(url)
        metadata.client_id.should == url
        metadata.application_type.should == "native"
        metadata.token_endpoint_auth_method.should == "none"
        metadata.confidential?.should be false
        metadata.grant_types.should == %w[authorization_code refresh_token]
        metadata.response_types.should == ["code"]
        metadata.scope.should == "atproto"
        metadata.redirect_uris.should == ["http://127.0.0.1/", "http://[::1]/"]
      end
    end

    it "should generate localhost metadata without a configured HTTP client" do
      AuthProto.configuration.http_client = nil
      described_class.from_url("http://localhost").scope.should == "atproto"
    end

    it "should decode scope and repeated redirect_uri parameters once while preserving the client ID" do
      scope = "atproto repo:app.bsky.feed.post rpc:app.bsky.feed.getTimeline?aud=*"
      redirects = ["http://127.0.0.1:9292/callback?next=%2Ffeed", "http://[::1]:8080/other"]
      url = "http://localhost/?" + URI.encode_www_form([
        ["scope", scope], ["redirect_uri", redirects.first], ["redirect_uri", redirects.last]
      ])
      metadata = described_class.from_url(url)
      metadata.client_id.should == url
      metadata.scope.should == scope
      metadata.redirect_uris.should == redirects
    end

    it "should accept percent-encoded spaces in scope" do
      described_class.from_url("http://localhost?scope=atproto%20transition%3Ageneric").scope.should == "atproto transition:generic"
    end

    ["scope=atproto&scope=atproto", "scope=&scope=atproto", "scope=atproto&%73cope=atproto"].each do |query|
      it "should reject duplicate scope parameters #{query.inspect}" do
        expect { described_class.from_url("http://localhost/?#{query}") }
          .to raise_error(AuthProto::InvalidClientMetadata, /multiple scope parameters/)
      end
    end

    ["", "other", "atproto  other", "atproto\tother"].each do |scope|
      it "should reject an invalid decoded scope #{scope.inspect}" do
        url = "http://localhost/?" + URI.encode_www_form(scope: scope)
        expect { described_class.from_url(url) }.to raise_error(AuthProto::InvalidClientMetadata, /scope/)
      end
    end

    ["", "/callback", "http://localhost:9292/callback", "https://127.0.0.1/callback",
     "http://example.com/callback", "http://127.0.0.2/callback", "http://user@127.0.0.1/callback",
     "http://127.0.0.1/callback#fragment", "http://127.0.0.1:0/", "http://127.0.0.1:65536/",
     "http%3A%2F%2F127.0.0.1%2Fcallback"].each do |redirect|
      it "should reject an invalid decoded redirect #{redirect.inspect}" do
        url = "http://localhost/?" + URI.encode_www_form(redirect_uri: redirect)
        expect { described_class.from_url(url) }.to raise_error(AuthProto::InvalidClientMetadata)
      end
    end

    ["http://localhost/path", "http://localhost//", "http://localhost:80/", "http://localhost:1234/",
     "http://user@localhost/", "http://@localhost/", "http://localhost/#fragment", "http://127.0.0.1/"].each do |url|
      it "should reject an invalid localhost client ID #{url.inspect} without fetching it" do
        expect { described_class.from_url(url) }.to raise_error(AuthProto::InvalidClientMetadata)
      end
    end

    it "should ignore query fields that do not configure virtual metadata" do
      metadata = described_class.from_url("http://localhost/?token_endpoint_auth_method=private_key_jwt")
      metadata.token_endpoint_auth_method.should == "none"
    end

    it "should support a client using virtual metadata without fetching a document" do
      url = "http://localhost/?" + URI.encode_www_form(redirect_uri: "http://127.0.0.1:9292/callback")
      client = AuthProto::Client.new(client_id: url, redirect_uri: "http://127.0.0.1:9292/callback")
      client.client_metadata.client_id.should == url
      client.client_metadata.redirect_uris.should == ["http://127.0.0.1:9292/callback"]
    end
  end

  describe ".from_url response validation" do
    before do
      @previous_configuration = AuthProto.configuration
      AuthProto.reset_configuration
      @http_client = mock("HTTP client")
      AuthProto.configuration.http_client = @http_client
    end

    after do
      AuthProto.configuration = @previous_configuration
    end

    [nil, false, [], "metadata", 42].each do |metadata|
      it "should reject a non-object JSON response #{metadata.inspect}" do
        @http_client.expects(:get).with(@valid_metadata["client_id"], follow_redirects: false)
          .returns(status: 200, headers: { "content-type" => "application/json" }, body: metadata.to_json)
        expect { described_class.from_url(@valid_metadata["client_id"]) }
          .to raise_error(AuthProto::InvalidClientMetadata, /must be a hash/)
      end
    end

    it "should translate a JSON parse error into InvalidClientMetadata" do
      @http_client.expects(:get).with(@valid_metadata["client_id"], follow_redirects: false)
        .returns(status: 200, headers: { "content-type" => "application/json" }, body: "{")
      expect { described_class.from_url(@valid_metadata["client_id"]) }
        .to raise_error(AuthProto::InvalidClientMetadata, /Invalid JSON/)
    end

    [201, 204, 301, 302, 303, 307, 308, 400, 500].each do |status|
      it "should reject HTTP #{status} even if the body contains valid metadata" do
        @http_client.expects(:get).with(@valid_metadata["client_id"], follow_redirects: false)
          .returns(status: status, headers: { "content-type" => "application/json" }, body: @valid_metadata.to_json)
        expect { described_class.from_url(@valid_metadata["client_id"]) }
          .to raise_error(AuthProto::InvalidClientMetadata, /expected HTTP 200 response for client metadata request/)
      end
    end

    [nil, "", "text/plain", "text/html", "application/did+json", "application/json-seq"].each do |content_type|
      it "should reject a missing or incorrect metadata Content-Type #{content_type.inspect}" do
        headers = content_type ? { "content-type" => content_type } : {}
        @http_client.expects(:get).with(@valid_metadata["client_id"], follow_redirects: false)
          .returns(status: 200, headers: headers, body: @valid_metadata.to_json)
        expect { described_class.from_url(@valid_metadata["client_id"]) }
          .to raise_error(AuthProto::InvalidClientMetadata, /Content-Type must be application\/json/)
      end
    end

    ["application/json", "application/json; charset=utf-8", "Application/JSON ; charset=UTF-8"].each do |content_type|
      it "should accept JSON metadata with Content-Type #{content_type.inspect}" do
        @http_client.expects(:get).with(@valid_metadata["client_id"], follow_redirects: false)
          .returns(status: 200, headers: { "Content-Type" => content_type }, body: @valid_metadata.to_json)
        described_class.from_url(@valid_metadata["client_id"]).client_id.should == @valid_metadata["client_id"]
      end
    end

    it "should reject a missing response body" do
      @http_client.expects(:get).with(@valid_metadata["client_id"], follow_redirects: false)
        .returns(status: 200, headers: { "content-type" => "application/json" }, body: nil)

      expect { described_class.from_url(@valid_metadata["client_id"]) }.to raise_error(
        AuthProto::InvalidClientMetadata, /client metadata request returned response with no body/
      )
    end

    it "should report a missing HTTP client" do
      AuthProto.configuration.http_client = nil

      expect { described_class.from_url(@valid_metadata["client_id"]) }.to raise_error(
        AuthProto::InvalidClientMetadata, /HTTP client not configured/
      )
    end
  end

  describe ".from_url redirect handling" do
    before do
      @previous_configuration = AuthProto.configuration
      AuthProto.reset_configuration
      AuthProto.configuration.http_client = AuthProto::HTTPClient.new
      Resolv::DNS.any_instance.stubs(:getaddresses).returns([Resolv::IPv4.create("93.184.216.34")])
    end

    after { AuthProto.configuration = @previous_configuration }

    [301, 302, 303, 307, 308].each do |status|
      it "should reject HTTP #{status} without requesting the redirect target" do
        url = @valid_metadata["client_id"]
        target = "https://other.example.com/metadata.json"

        stub_request(:get, url)
          .to_return(status: status, headers: { "Location" => target })
        stub_request(:get, target)
          .to_return(status: 200, headers: { "Content-Type" => "application/json" }, body: @valid_metadata.to_json)

        expect { described_class.from_url(url) }.to raise_error(
          AuthProto::InvalidClientMetadata, /expected HTTP 200 response for client metadata request/
        )

        WebMock.should_not have_requested(:get, target)
      end
    end
  end

  describe "#confidential?" do
    it "should return true for confidential clients using private_key_jwt" do
      @valid_metadata["token_endpoint_auth_method"] = "private_key_jwt"
      @valid_metadata["token_endpoint_auth_signing_alg"] = "ES256"
      @valid_metadata["jwks"] = { "keys" => [] }
      client_metadata = AuthProto::ClientMetadata.new(@valid_metadata)
      client_metadata.confidential?.should be true
    end

    it "should return false for non-confidential clients" do
      client_metadata = AuthProto::ClientMetadata.new(@valid_metadata)
      client_metadata.confidential?.should be false
    end
  end
end
