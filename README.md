# AuthProto

[![Gem Version](https://badge.fury.io/rb/authproto.svg?icon=si%3Arubygems&icon_color=%23ff6251)](https://rubygems.org/gems/authproto) [![YARD Docs](http://img.shields.io/badge/yard-docs-blue.svg)](https://rubydoc.info/gems/authproto)

A Ruby implementation of an OAuth 2.1 client for use in AT Protocol apps.

Originally released as [atproto_auth](https://github.com/jhuckabee/atproto_auth) by Josh Huckabee in 2024, this is a fork that continues the development.

> [!NOTE]
> Part of ATProto Ruby SDK: [ruby.sdk.blue](https://ruby.sdk.blue)


## Features

The library supports all features of OAuth required by ATProto:

- DPoP (Demonstrating Proof of Possession) and nonce management
- client, resource server, and authorization server metadata JSON
- PAR (Pushed Authorization Requests)
- PKCE (Proof Key for Code Exchange)
- client assertions for confidential clients

Both public and confidential clients are supported. The main intended use case is backend apps which users authorize to access their ATProto accounts server-side (likely as a confidential client), but it's also possible to use the library in command-line scripts (although in many cases app passwords might still be a better solution for those right now).

The gem manages the storage of session data and DPoP nonces, and handles at rest encryption of the stored tokens. SQLite, Redis and in-memory storage backends are included.

There is also an (a bit experimental) adapter for using AuthProto with the [Minisky gem](https://tangled.org/mackuba.eu/minisky) to make XRPC requests with OAuth login support.

> [!NOTE]
> This gem deliberately does not support any features, profiles and configurations of OAuth that are not currently
used in ATProto, and it does not support turning off any additional requirements and restrictions that ATProto
introduces on top of standard OAuth specifications. For example, DPoP with server nonces, PAR, and PKCE are always required, and the client ID must be a URL from which the client metadata is fetched.
>
> It will likely not be of much use in non-ATProto contexts. This is intentional, in order to not make the project more complicated than it already is.


## Status

The project was originally written in 2024. I have forked it, reviewed the code, refactored a lot of it, and made a lot of bug fixes to make everything more up to date and compliant with current ATProto OAuth. It has a pretty complete test coverage (converted from Minitest to RSpec), and it has been reviewed by a few AI agents, with no major outstanding issues left at the moment.

I'm not currently using it in production at all yet, so consider this still alpha quality. Might kill your cat, steal your girlfriend, and so on…

The public API will likely be changing in some initial releases. The `AuthProto::Client` entry point will likely be the most stable part, but treat most of the rest of the library as private API / implementation detail for now.


## Installation & requirements

AuthProto requires Ruby version 3.3 or newer (versions 3.2 and older no longer receive maintenance updates). Tested on versions up to 4.0.

To use it in your app, add this to your `Gemfile`:

    gem 'authproto'

Depending on the configured storage, you will also need to add either the `sqlite3` gem or the `redis` gem, and `minisky` if you want to use the Minisky XRPC client. These are not explicit dependencies so they're not forced on you if you don't need them.


## Initial configuration

The first thing you need to do is to set up a few required things in the global configuration:

```rb
AuthProto.configure do |config|
  ...
end
```

There are two required settings to be configured:

### <u>http_client:</u>

This configures a HTTP client for making requests to the authorization server and to metadata endpoints during the initial authorization process and later token refreshing (**not** for later authorized data requests to the PDS). Set it either to an instance of the default `AuthProto::HTTPClient`, or a compatible custom implementation/adapter.

```rb
config.http_client = AuthProto::HTTPClient.new
```

### <u>storage:</u>

This configures the storage adapter for storing session data and DPoP nonces.

The available options are:

* an SQLite database (`AuthProto::Storage::SQLite`, requires additionally the `sqlite3` gem)
* a Redis database (`AuthProto::Storage::Redis`, requires additionally the `redis` gem)
* an in-memory storage for testing (`AuthProto::Storage::Memory`)
* it's also possible to implement a custom storage adapter, providing the same interface (see `AuthProto::Storage::Interface`)

A basic configuration may look like this:

```rb
require 'authproto'

AuthProto.configure do |config|
  config.http_client = AuthProto::HTTPClient.new(timeout: 10)

  config.storage = AuthProto::Storage::SQLite.new(
    path: File.join(__dir__, "db", "localhost_auth.sqlite3")
  )
end
```

The `AuthProto::Storage::Memory` adapter is configured by default, so you can skip the `storage` part if you want to use it.

### ATPROTO_MASTER_KEY:

This is technically not required, but you'll want to set it for anything more than brief testing. In the session storage, things like state token and access tokens are encrypted at rest using a key read from an ENV var `ATPROTO_MASTER_KEY`. The var needs to be Base64-encoded, and 32 bytes long when decoded.

You can generate it e.g. like this:

```
openssl rand -base64 32
```

And then set it e.g. by adding `ATPROTO_MASTER_KEY=...` on the command line, or with `export`, or with something like [dotenv](https://github.com/bkeepers/dotenv).

If you don't set it, you will see a warning like this:

```
WARNING: Using randomly generated encryption key - tokens will not persist across restarts
```


## Usage

The main class and the entry point to the library is the `AuthProto::Client` class. You will likely only need to create and use this one directly.

The initializer looks like this:

```rb
client = AuthProto::Client.new(
  client_id: "https://...",
  redirect_uri: "https://...",
  metadata: { ... },
  signing_key: signing_key
)
```

The first two arguments are required, the other two are optional. What you put into these will depend on how you're running the app: on a publicly accessible server or on localhost, and as a public or a confidential client.


### <u>On a production server</u>

The normal, expected way to run an OAuth app is that you have a publicly accessible server (with HTTPS) on which you can at least host the client metadata JSON file – even if you're building e.g. a native iOS app. This can be a completely static site hosting just the JSON file, if you don't need anything else, but it needs to be there (though in case of a Ruby app, you will also need some kind of callback endpoint to receive authorization codes).

The metadata can technically be located at any path you want, but it's strongly recommended to put it at `/oauth-client-metadata.json`: this will make the PDS display your app as just a hostname, like "_**foobar.com** wants to access your account_", otherwise the full URL with the path will be shown, which looks less friendly.

Client metadata is a JSON file that includes information about your app like the name and requested permissions, and the enabled security features. What exactly goes into it is a bit beyond the scope of this readme, you can see the details in the [ATProto OAuth spec](https://atproto.com/specs/oauth#client-id-metadata-document).

Once you have the file readable on the server, you can create the `Client` passing it the `client_id` – which is the full URL to the metadata JSON file – and a `redirect_uri` to which the user's browser will be redirected after authorization:

```rb
client = AuthProto::Client.new(
  client_id: "https://site.example.com/oauth-client-metadata.json",
  redirect_uri: "https://site.example.com/callback"
)
```

If you host the metadata file from the same codebase, you can also include the `metadata` here inline as a Hash. It's not required – it will be fetched from the live URL here otherwise – but if you do, it saves you one request whenever `Client` is created. (Note, this is a fetch on the *client* side so the library can get more info about the app and validate it – the *authorization server* will still need to fetch this JSON file even if you provide the `metadata` here.)


### <u>Confidential clients</u>

The example above is for a **public client**; this has nothing to do with it running on a public server – a "public client" is one that doesn't have a set of secret signing keys kept server-side, and those get shorter access & refresh token lifetimes.

The other type is a **confidential client**; to run one, you need a set of keys to sign *client assertions*. The key is a JSON representation of an elliptic curve key in the form of a [JWK (JSON Web Key)](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets), like this:

```json
{
  "kty": "EC",
  "crv": "P-256",
  "kid": "key-1",
  "x": "1vhfr8lFBg0jhXMNoXn-XWtpxR9nu8Ja1JGFrWqDIV8",
  "y": "sBgQICMTA8MBeD_TgdJduJmmhEQ9pA5l4EPUBtBeZOg",
  "d": "rqnhaaobMsqhWAnCWJGzioXbrqBFQ_59I2dhF_cw1dA",
  "use": "sig"
}
```

This is a private key, a public key lacks the `d` field. You can generate those e.g. using this [generate_keys.rb script](https://tangled.org/mackuba.eu/authproto/blob/readme/examples/confidential_client/scripts/generate_keys.rb) from the example app in [examples folder](https://tangled.org/mackuba.eu/authproto/tree/readme/examples/) here.

Once you have the keys, put the public one under `jwks.keys` in the metadata JSON:

```json
{
  ...
  "jwks": {
    "keys": [{ "x": ... }]
  }
}
```

And pass the private one as `signing_key` to the `Client`:

```rb
client = AuthProto::Client.new(
  client_id: "https://site.example.com/oauth-client-metadata.json",
  redirect_uri: "https://site.example.com/callback",
  signing_key: { x: ... }
)
```

You also need these fields set in the metadata JSON like this:

```json
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "ES256",
```

With a setup like this, you get much longer potential session length, assuming correctly implemented token refresh.


### <u>Testing on localhost</u>

Running OAuth on localhost is a bit of a special exception, it doesn't work the way it works normally:

* the `client_id` URL needs to be `http://localhost/`, **without a port**, and with this literal hostname, **not as a loopback IP**
* the metadata JSON file isn't fetched from the URL, but it's instead generated from preset values and from URL query parameters (`Client` will reject a `metadata` parameter here)
* you can configure `redirect_uri` and `scope` by appending them as query params (with encoded values) to the `client_id`
* the `redirect_uri` needs to be on `127.0.0.1` or `[::1]` IP (likely with a port), **not** on `localhost`, confusingly
* the app will always be a "public" client, not a "confidential" one

So an example setup could look like this:

```rb
redirect_uri = "http://127.0.0.1:8000/callback"
scope = "atproto repo:app.bsky.feed.post"

client_id = "http://localhost/?" + URI.encode_www_form({
  redirect_uri: redirect_uri,
  scope: scope
})

# "http://localhost/?redirect_uri=http%3A%2F%2F127.0.0.1%3A8000%2Fcallback" +
#   "&scope=atproto+repo%3Aapp.bsky.feed.post"

client = AuthProto::Client.new(
  client_id: client_id,
  redirect_uri: redirect_uri
)
```

AuthProto also includes a helper called `LocalhostServer`, which starts a temporary localhost HTTP server inline just to receive the callback request, and returns the received codes to the block you pass to it:

```rb
AuthProto::LocalhostServer.start(client.client_metadata) do |json|
  client.handle_callback(**json, expected_session_id: session_id)
end
```


## Using the Client

Regardless of the configuration, the rest of the API is the same. The expected steps are:


### Create an authorization URL

You can start the authorization process either with a specific user handle/DID – then their PDS will be looked up and they will be redirected there and asked to log in with this specific account – or from a PDS URL, in which case they will go to the PDS's site, but presented with a login form or account selection:

```rb
client.authorize(handle: 'user.handle', scope: 'atproto ...')
client.authorize(pds: 'https://pds.example.com', scope: 'atproto ...')
```

This returns a hash like:

```rb
{
  url: "https://lab.martianbase.net/oauth/authorize?request_uri=.....",
  session_id: "20044fc4-1131-47f9-90f8-99c26fe82a00"
}
```

Depending on your app, either redirect the user to this URL, or present it to the user and ask them to open it and log in there. Write down this session ID too – you'll need it in a moment (for a web app, store it e.g. in a session variable).


### Handle the callback request

After the user approves or rejects the request, they will be redirected to your configured `redirect_uri`. Check the received params for an `error` key – if it's set, handle the error in some appropriate way.

If there's no error, pass the received values back to `Client` to the `#handle_callback` method. Note: you will need to also pass the ID of the session from which the login was initiated. This is to make sure that we don't log in a user completing authorization into *another user's* account:

```rb
client.handle_callback(
  code: params[:code],
  state: params[:state],
  iss: params[:iss],
  expected_session_id: session[:session_id]
)
```


### Make authenticated data requests

This part is… a bit complicated, because this API is designed to allow working with any HTTP client library you're using. `AuthProto::Client` by itself doesn't implement a full XRPC client for making requests and handling responses. What it gives you is a way to get a set of authentication headers generated for a specific request (method + URL) that you can then pass to e.g. `Net::HTTP` or [Faraday](https://github.com/lostisland/faraday):

```rb
endpoint = "https://#{pds_host}/xrpc/com.atproto.repo.createRecord"
oauth_session = client.session_manager.get_session(session_id)

headers = client.auth_headers(
  session_id: session_id,
  method: 'POST',
  url: endpoint
)

connection = Faraday.new do |f|
  f.request :json
end

res = connection.post(endpoint) do |req|
  headers.each { |key, value| req.headers[key] = value }

  req.body = {
    repo: oauth_session.did,
    collection: "app.bsky.feed.post",
    record: {
      text: "Hello world!",
      langs: ["en"],
      createdAt: Time.now.utc.iso8601(3)
    }
  }
end
```

One additional complication is **DPoP** and its changing *nonces*. The server gives you a "nonce" that you need to use to generate the "proof" header, which changes after at most 5 minutes, so the requests will often fail with a header indicating a new nonce to use.

You handle this by passing the response headers to `client.dpop_client` like this to let it update the nonce. The method expects the response as a hash of `{ headers, body, status }` (since different HTTP libraries will return it in a different format):

```rb
response = { headers: res.headers, body: res.body, status: res.status }

client.dpop_client.process_response(response,
  server_url: endpoint,
  session_id: session_id
)
```

Then, ask the `dpop_client` to check if the response contains a nonce error, and if so, you'll need to retry the whole request once again (with new headers):

```rb
if client.dpop_client.has_nonce_error?(response)
  make_request(...)
end
```

You can also use the `with_nonce_handling` helper, passing it a block which makes a request (remember to call `auth_headers` *inside* the block, since on the repeated call the headers will be different) and returns the response in the hash format:

```rb
endpoint = "https://#{pds_host}/xrpc/com.atproto.repo.createRecord"
oauth_session = client.session_manager.get_session(session_id)

connection = Faraday.new do |f|
  f.request :json
end

post_record = {
  repo: oauth_session.did,
  collection: "app.bsky.feed.post",
  record: {
    text: "Hello world!",
    langs: ["en"],
    createdAt: Time.now.utc.iso8601(3)
  }
}

response = client.dpop_client.with_nonce_handling(session_id, endpoint) do
  headers = client.auth_headers(
    session_id: session_id,
    method: 'POST',
    url: endpoint
  )

  res = connection.post(endpoint) do |req|
    headers.each { |key, value| req.headers[key] = value }
    req.body = post_record
  end

  { headers: res.headers, body: res.body, status: res.status }
end
```

For a more batteries-included client API, see [Minisky](#minisky-adapter) below.


### Refresh the tokens

The access tokens usually have a lifetime of around 15-30 minutes, and after that time, you will get a 401 error (or `Client` can raise `Client::TokenError` if it detects an expired token earlier). In that case, call `refresh_token` to use the other token you got (the refresh token) to get a new access token:

```rb
client.refresh_token(session_id)
```


### Log the user out

Finally, if you want to log the user out, call `delete_session` to clear the session from the configured storage:

```rb
client.delete_session(session_id)
```

You can also pass `revoke: true` to additionally revoke the tokens on the PDS:

```rb
client.delete_session(session_id, revoke: true)
```


## Minisky adapter

AuthProto also includes an adapter for the [Minisky gem](https://tangled.org/mackuba.eu/minisky) for making XRPC requests, which gives you a client with a slightly more high-level API that handles the authenticated requests for you.

The API is a bit of a mix of a standard password-auth Minisky client and the `AuthProto::Client` for the initial authentication:

```rb
# needs to be required separately
# and requires `gem 'minisky'` in the Gemfile
require 'authproto/minisky'

sky = Minisky::OAuthClient.new(pds_host,
  client_id: "https://#{server_hostname}/oauth-client-metadata.json",
  redirect_uri: "https://#{server_hostname}/callback",
  metadata: metadata,       # or nil/skip
  session_id: session_id,   # or nil/skip
  signing_key: signing_key  # or nil/skip
)

auth = sky.authorize(pds: "https://#{pds_host}", scope: "atproto ...")
p auth[:url]
# ...

sky.handle_callback(**params, expected_session_id: auth[:session_id])
```

and then e.g.:

```rb
sky.get_request('app.bsky.feed.getTimeline', { limit: 100 })

sky.post_request('com.atproto.repo.createRecord', { repo: ..., ... })

posts = sky.fetch_all('app.bsky.graph.getFollows', { actor: did }, field: 'follows')
```

It also handles automatically the nonce updates and token refresh. Unlike `AuthProto::Client`, `Minisky::OAuthClient` handles a single session at a time.

This class is a bit more experimental and likely to change in future versions (pending a redesign of the Minisky internal architecture).


## Additional configuration

Some other things you can configure through `AuthProto.configure`:

* `client_assertion_lifetime` – how long a client assertion is valid for a confidential client (default: 5 min)
* `dpop_nonce_lifetime` – how long a DPoP nonce is valid (default: 5 min)
* `pending_session_ttl` – how long a session that hasn't completed authentication with a callback is valid (default: 15 min)

You shouldn't generally need to change those defaults.


## Other resources

- [YARD API documentation](https://rubydoc.info/gems/authproto) at rubydoc.info
- [ruby.sdk.blue](https://ruby.sdk.blue)
- [ATProto OAuth specification](https://atproto.com/specs/oauth)

## Credits

Copyright © 2026 Kuba Suder ([@mackuba.eu](https://bsky.app/profile/did:plc:oio4hkxaop4ao4wz2pp3f4cr)).

Original AtprotoAuth copyright © 2024 Josh Huckabee.

The code is available under the terms of the [MIT license](https://tangled.org/mackuba.eu/authproto/blob/main/MIT-LICENSE.txt). Bug reports and pull requests are welcome 😎
