# AuthProto

[![Gem Version](https://img.shields.io/gem/v/atproto_auth.svg)](https://rubygems.org/gems/atproto_auth)
[![Documentation](https://img.shields.io/badge/docs-rdoc-blue.svg)](https://www.rubydoc.info/gems/atproto_auth)

A Ruby implementation of the [AT Protocol OAuth specification](https://atproto.com/specs/oauth). This library provides support for both client and server-side implementations, with built-in security features including [DPoP](https://datatracker.ietf.org/doc/html/rfc9449), [PAR](https://datatracker.ietf.org/doc/html/rfc9126), and dynamic client registration.

## Features

- Complete AT Protocol OAuth 2.0 implementation
- Secure by default with mandatory DPoP and PKCE
- Support for confidential (backend) and public clients
- Thread-safe session and token management
- Comprehensive identity resolution and verification
- Automatic token refresh and session management
- Robust error handling and recovery mechanisms
- Configurable storage backends with built-in SQLite and Redis support
- Encrypted storage of sensitive data

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'atproto_auth'
```

And then execute:

```sh
bundle install
```

Or install it yourself as:

```sh
gem install atproto_auth
```

## Requirements

- Ruby 3.3 or higher
- OpenSSL support
- For confidential clients: HTTPS-capable domain for client metadata hosting
- Optional: SQLite or Redis storage adapter gems for production use

## Basic Usage

### Configuration

```ruby
require 'atproto_auth'

AuthProto.configure do |config|
  # Configure HTTP client settings
  config.http_client = AuthProto::HTTPClient.new(
    timeout: 10,
    verify_ssl: true
  )

  # Set token lifetimes
  config.default_token_lifetime = 300 # 5 minutes
  config.dpop_nonce_lifetime = 300  # 5 minutes

  # Configure storage backend (default is in-memory)
  config.storage = AuthProto::Storage::Memory.new
end

# Storage adapter gems are optional dependencies. Add one of these:
gem 'sqlite3', '~> 2.9'
gem 'redis', '~> 5.4'
```

### Local HTTP debugging

For debugging a flow that needs both local HTTP and remote HTTPS (handle/PLC
resolution, metadata discovery and OAuth requests), explicitly select:

```ruby
AuthProto.configure do |config|
  config.http_client = AuthProto::InsecureHTTPClient.new(timeout: 10)
end
```

`InsecureHTTPClient` accepts HTTP and HTTPS, including loopback and private-network
destinations, and permits redirects between them. It disables the regular client's
scheme/IP restrictions for development; HTTPS certificate verification stays enabled
by default. Timeouts, response size limits and request headers are inherited.

The regular `HTTPClient` accepts HTTPS and rejects loopback/private addresses.
Use it for remote OAuth servers, including when your application's callback is
local: the browser, rather than this HTTP client, follows the callback redirect.

Client metadata fetches call `get(url, follow_redirects: false)` and require HTTP
200 with an `application/json` response. Custom HTTP clients must support this
keyword and return the initial response without following redirects when it is false.

Client metadata must explicitly set `token_endpoint_auth_method` to `none` for
public clients or `private_key_jwt` for confidential clients. Omitting it defaults
to `client_secret_basic` in OAuth metadata, which this library does not support.

### Storage Backends

The library supports multiple storage backends for managing OAuth state:

#### In-Memory Storage (Default)

```ruby
# Default configuration - good for development
AuthProto.configure do |config|
  config.storage = AuthProto::Storage::Memory.new
end
```

#### SQLite Storage

SQLite can be used for persistent storage in development or in production setups with
low-to-moderate write concurrency:

```ruby
AuthProto.configure do |config|
  config.storage = AuthProto::Storage::SQLite.new(
    path: '/var/lib/my_app/atproto_auth.sqlite3'
  )
end
```

Add the adapter gem to your Gemfile:

```ruby
gem 'sqlite3', '~> 2.9'
```

#### Redis Storage

Use Redis for production deployments with multiple hosts or write-heavy scenarios:

```ruby
require 'redis'

AuthProto.configure do |config|
  redis_client = Redis.new(
    url: ENV['REDIS_URL'],
    ssl_params: { verify_mode: OpenSSL::SSL::VERIFY_PEER }
  )
  
  config.storage = AuthProto::Storage::Redis.new(
    redis_client: redis_client
  )
end
```

Add the adapter gem to your Gemfile:

```ruby
gem 'redis', '~> 5.4'
```

#### Custom Storage Implementation
```ruby
# Implement your own storage backend
class CustomStorage < AuthProto::Storage::Interface
  def set(key, value, ttl: nil)
    # Implementation
  end

  def get(key)
    # Implementation
  end

  def delete(key)
    # Implementation
  end

  def exists?(key)
    # Implementation
  end

  def with_lock(key, ttl: 30)
    # Implementation
  end
end
```

### Confidential Client Example

Here's a basic example of using the library in a confidential client application:

```ruby
# Initialize client with metadata
client = AuthProto::Client.new(
  client_id: "https://app.example.com/oauth-client-metadata.json",
  redirect_uri: "https://app.example.com/callback",
  metadata: {
    # Your client metadata...
  }
)

# Start authorization flow
auth = client.authorize(
  handle: "user.bsky.social",
  scope: "atproto"
)

# Use auth[:url] to redirect user

# Handle callback
tokens = client.handle_callback(
  code: params[:code],
  state: params[:state],
  iss: params[:iss]
)

# Make authenticated requests
headers = client.auth_headers(
  session_id: tokens[:session_id],
  method: "GET",
  url: "https://api.example.com/resource"
)
```

For a complete working example of a confidential client implementation, check out the example application in `examples/confidential_client/`. This Sinatra-based web application demonstrates:
- Complete OAuth flow implementation
- Session management
- DPoP token binding
- Making authenticated API requests
- Proper error handling
- Key generation and management

See `examples/confidential_client/README.md` for setup instructions and implementation details.

### Public Client Example

```ruby
client = AuthProto::Client.new(
  client_id: "https://app.example.com/oauth-client-metadata.json",
  redirect_uri: "https://app.example.com/callback"
)

# Browser will open authorization URL
auth = client.authorize(
  handle: "user.bsky.social",
  scope: "atproto"
)

# After callback, exchange code for tokens
tokens = client.handle_callback(
  code: params[:code],
  state: params[:state],
  iss: params[:iss]
)
```

## Features In Detail

### Identity Resolution

The library uses DIDKit for AT Protocol identity resolution:

- Handle to DID resolution (DNS-based or HTTP fallback)
- DID document fetching and validation
- PDS (Personal Data Server) location verification
- Bidirectional handle verification
- Authorization server binding verification

### Token & Session Management

Comprehensive token lifecycle management:

- Secure token storage with encryption
- Automatic token refresh
- DPoP proof generation and binding
- Session state tracking
- Cleanup of expired sessions

### Security Features

Built-in security best practices:

- Mandatory PKCE for all flows
- DPoP token binding
- Constant-time token comparisons
- Thread-safe state management
- Protection against SSRF attacks
- Secure encrypted token storage
- Atomic storage operations with locking

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `bundle exec rspec` (or `bundle exec rake spec`) to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/jhuckabee/atproto_auth.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
