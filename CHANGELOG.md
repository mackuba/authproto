## [Unreleased]

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
