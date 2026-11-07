## Unreleased

- added `process_dpop`, `has_nonce_error?` and `with_nonce_handling` helpers to `Client`, proxying the calls to `dpop_client` for easier access
- added `Client#http` which lets you access the global HTTP client
- added `Client.for_localhost` and `Minisky::OAuthClient.for_localhost` for creating a localhost client with metadata encoded in the `client_id` query params
- added `Minisky::OAuthClient.with_oauth_client` to reuse an existing `AuthProto::Client` instead of creating a new one
- added `Minisky::OAuthClient#did`
- renamed `server_url` params to `url` in `Client`, `DPoP::Client` and `DPoP::NonceManager` and to `origin` in `StoredNonce`
- `Client` now rejects a `metadata` hash passed in argument for localhost clients (since you need to put the values into the `client_id` query params anyway for the server to read them)
- `Client#handle_callback` now takes the callback parameters as a single Hash parameter instead of keyword args
- `uri:` and `url:` arguments across the project now accept also `URI` objects
- response hashes are now accepted also having status code as a String and header values as array, so you can now pass e.g. a `Net::HTTPResponse` as: `{ status: res.code, headers: res.to_hash, body: res.body }`
- `Minisky::OAuthClient` doesn't require a PDS hostname anymore to create an instance
- added `AuthProto.storage.cleanup_expired_records`

## [0.3.0.beta4] – 2026-11-03

- at the end of authentication that started with a PDS URL, verify that the received DID belongs to that PDS
- revoke received tokens if after authentication the DID or PDS doesn't match the previously known value
- check if the known PDS matches before doing a token refresh
- fixed decryption code accepting encrypted data with truncated tags
- fixed token refresh failing if some originally requested scopes were not granted (e.g. email access)
- fixed token refresh losing the old refresh token if it wasn't actually replaced
- improved validation of token exchange & token refresh response, and client & resource/authorization server metadata
- added `#granted_scope`, `#has_limited_scope?` and `#can_be_revoked?` to `Session`
- added option to explicitly revoke access/refresh tokens on the server when deleting a session, with `delete_session(id, revoke: true)`
- require the `ATPROTO_MASTER_KEY` to be exactly 32 bytes long (or 44 Base64 characters)
- require https:// URLs in DPoP client and nonce manager (since resource servers / PDSes and authorization servers need to be on HTTPS)
- reject token responses with the OpenID `id_token` field
- when loading a session, verify that it has been created with the same `client_id`
- ignore the redirect URI's port when testing if the redirect URI passed for authentication for a localhost client is included on the metadata list (as the spec says)

## [0.3.0.beta3] – 2026-11-02

- session's state token is deleted on successfully completed authentication (i.e. `handle_callback`)
- pending sessions (that haven't completed authentication) are stored with a TTL of 15 minutes by default, and expire after that; this can be changed through `pending_session_ttl` in the global configuration
- completed but non-renewable session (without a refresh token) are set with a TTL such that they expire when their access token expires
- fixed deleting a session's state token in `Client#delete_session`
- DPoP keys are now connected to a specific session and saved & restored with it; multiple sessions used from the same `AuthProto::Client` will have proofs signed with different DPoP keys, and the keys are automatically restored and don't need to be passed in the argument to `Client` or `Minisky::OAuthClient`
- DPoP nonces are now stored separately per session and per service, not just one per service
- the `minisky_console` example now supports restoring previous sessions using session ID
- for security, `Client#handle_callback` and `Minisky::OAuthClient#handle_callback` now require an `expected_session_id:` argument, where you need to pass a session ID previously saved from the output of `authorize` in browser storage or a local variable; token callback is rejected if the passed saved session ID doesn't match the ID of the session looked up using the state token from the callback
- added `Session#pending?` and `Session#tokens_valid?`
- removed unused `default_token_lifetime` and `encryption` configuration settings
- added `client_assertion_lifetime` configuration setting
- nonce manager now uses the global `dpop_nonce_lifetime` ttl setting by default
- simplified the DPoP public key JWT included in headers
- improved validation of nonce-related headers & responses, client metadata, refresh errors, and assertion signing keys
- sessions store the client assertion signing key's ID in the metadata and check it when deserialized
- various refactors and reorganizations

## [0.3.0.beta2] – 2026-10-31 👻

- private keys for signing are now passed separately as `signing_key:` instead of being taken from the same `jwks` in the metadata that holds public keys
- generate localhost metadata from `client_id` params
- `confidential_client`: validate `SESSION_SECRET` before start and throw an error early
- additional validations for URLs, resource server and authorization server metadata, and PAR request and response
- set `code_challenge_method` in the PAR request automatically to `S256`
- various renames, refactors, cleanups
- encode '*' in the authorization URL – unencoded asterisk might break click-to-open-URL in some terminals
- strip query part from URLs in `htu` in the DPoP proof generator
- keep existing query part in the PAR authorization endpoint when adding params to it
- verify that all scopes passed during authorization are declared in client metadata
- don't reuse client assertion JWT on retried requests
- POST redirects are not allowed, GET redirects are disabled by default

## [0.3.0.beta1], as AuthProto – 2026-10-28

- modernized code
- various renames, refactors, cleanups
- removed some unused code
- removed strict dependency on the Redis gem
- added alternative SQLite storage
- added HTTP client version that allows `http://` connections
- added experimental Minisky adapter and `minisky_console` example
- added temporary in-process `localhost` HTTP server for receiving callbacks inside `irb`
- additional validations for request IPs and URLs, responses, and client metadata
- fixed `confidential_example` running on localhost
- updated `confidential_example` with a UI for making a test post to Bluesky
- updated examples to use `oauth-client-metadata.json` instead of `client-metadata.json`
- converted test suite to RSpec
- replaced `Identity` module with DIDKit
- fixed randomly generated encryption key not being shared between different parts of the app
- fixed some token refresh code failing due to wrong exception names
- don't try to add client assertions for public clients
- switched to JWT gem version 3.x


---

# Earlier releases as `atproto_auth`:

## [0.2.5] – 2024-12-13

Fixed:

- Additional token refresh edge case handling

## [0.2.4] – 2024-12-13

Fixed:

- Token refresh now correctly handles expired tokens

## [0.2.2] – 2024-12-12

Added:

- Added support for did:web users

## [0.2.1] – 2024-12-11

Fixed:

- Fixed a bug with access token hash generation

## [0.2.0] – 2024-12-10

Added:

- Client#handle_callback now returns session did as part of the response

## [0.1.0] – 2024-12-07

Added:

- Configurable storage backend system for managing OAuth state
- In-memory storage implementation included by default
- Redis storage implementation for production environments
- Thread-safe storage operations with atomic locks
- Storage encryption for sensitive data
- Automatic cleanup of expired tokens and session data
- Storage interface for custom backend implementations

Changed:

- Storage configuration is now required in AtprotoAuth.configure
- Default configuration uses thread-safe in-memory storage
- Session and token management now use configured storage backend
- Improved thread safety for all storage operations

## [0.0.1] – 2024-12-05

- Initial release
