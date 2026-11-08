# Bluesky bookmarks example

A Sinatra app in `app/server.rb` with a separate `app/bookmark.rb` model, using
`Minisky::OAuth`, AuthProto, ActiveRecord 8.1, and `sinatra-activerecord`.
Sign in with a handle, fetch private bookmarks, and browse
them newest first, 20 per page. Search returns every bookmark containing the given
text, without pagination. Everything is rendered with ERB; no JavaScript or workers.

The only API permission is
`rpc:app.bsky.bookmark.getBookmarks?aud=*`, alongside the required
`atproto` scope. Requests go through the account's PDS to the Bluesky AppView.

After login, DIDKit resolves the authenticated account's verified handle. The app
saves it in the browser session and displays it as `@handle`. If the lookup fails
or no verified handle is available, it displays the account DID instead.

## Run on localhost

Use Ruby 3.3 or newer (for example, through `asdf`). From this directory:

```sh
bundle install
cp config/oauth-client-metadata.localhost.json config/oauth-client-metadata.json
```

Generate two persistent secrets:

```sh
openssl rand -base64 32
openssl rand -hex 32
```

Put the first value in `ATPROTO_MASTER_KEY` and the second in `SESSION_SECRET` in `.env`:

```dotenv
ATPROTO_MASTER_KEY=BASE64_VALUE
SESSION_SECRET=HEX_VALUE
```

Then create the bookmarks table and start the app:

```sh
bundle exec rake db:migrate
bundle exec rackup -o 127.0.0.1 -p 9292
```

Open <http://127.0.0.1:9292> and sign in. Use that address throughout the login flow;
the browser cookie must be available at the callback on the same host. Localhost
clients are always public. The app builds the localhost client ID with its callback
URI and scope encoded as query parameters.

Click **Fetch your bookmarks** on the signed-in page to import all API pages in the
request. This can take a while for a large collection. **Fetch bookmarks again**
repeats the full import, updating existing entries without creating duplicates.

## Fetch newer bookmarks from rake

After signing in through the web app, use the owner DID shown on the bookmarks page:

```sh
bundle exec rake 'bookmarks:fetch[did:plc:YOUR_ACCOUNT_DID]'
```

Alternatively, use `DID=did:plc:YOUR_ACCOUNT_DID bundle exec rake bookmarks:fetch`.
The task resumes that account's most recently saved OAuth session from SQLite,
refreshing tokens through Minisky when needed. It follows API cursors until it
reaches bookmarks at or before the newest locally saved bookmark timestamp. If
there are no saved bookmarks, it fetches the entire collection.

Run with the same configuration and `ATPROTO_MASTER_KEY` as the web app. Signing
out revokes that browser's OAuth session, so sign in again before using the task
if it was the account's saved session.

## Live deployment

Copy `config/oauth-client-metadata.production.json` to
`config/oauth-client-metadata.json` and replace `YOUR_DOMAIN_HERE` in both URLs.
Set these variables in the environment or `.env`:

```dotenv
RACK_ENV=production
PERMITTED_DOMAIN=bookmarks.your-domain.com
ATPROTO_MASTER_KEY=YOUR_PERSISTENT_BASE64_KEY
SESSION_SECRET=YOUR_PERSISTENT_SESSION_SECRET
```

The production template runs as a **public** client. For a **confidential** client,
run this after configuring the production metadata:

```sh
bundle exec ruby scripts/generate_keys.rb
```

This writes the private ES256 signing key to `config/keys.json` and updates the
metadata with the public key and `private_key_jwt` settings. Keep the private key
on the server. To switch back to public mode, remove the private key file and
restore `token_endpoint_auth_method: "none"`, removing `jwks` and
`token_endpoint_auth_signing_alg` from the metadata.

Run the migration, then start the server behind an HTTPS reverse proxy:

```sh
bundle exec rake db:migrate
bundle exec rackup -E production -o 127.0.0.1 -p 9292
```

Forward the original host and HTTPS scheme to Rack. The metadata endpoint
`/oauth-client-metadata.json` must be publicly reachable at the registered client
ID. In production, session cookies require HTTPS. Configure the proxy/request
timeout to allow a synchronous full import to finish.

## Storage and import behavior

- `db/authproto.sqlite3`: AuthProto sessions, encrypted tokens, and DPoP state.
- `db/bookmarks.sqlite3`: `accounts` with `did`, `fetched`, and `session_id`, and
  `bookmarks` with `account_id`, `uri`, `author_handle`, `created_at` (bookmark time),
  `posted_at` (post time), and `text`. Each account has many bookmarks. The migration
  adds a unique DID index, a foreign key, `(account_id, created_at DESC)`, and unique
  `(account_id, uri)` indexes.

Run `bundle exec rake db:migrate` when updating an existing installation. Cached
bookmarks are preserved and linked to accounts, with `fetched` set to true for
those accounts. Sign in again to populate each account's `session_id`; old custom
records in the AuthProto store are no longer used. New accounts start unfetched.

Every query is scoped to the signed-in owner's DID. Imports skip blocked/missing
posts and posts with blank text; embeds are ignored. The post date links to
`bsky.app` using the author DID and record key from the AT URI. If the API omits a
bookmark's optional `createdAt`, it is stored as `NULL` and sorts after dated
bookmarks; the app does not substitute the post date or import time.

Search treats `%`, `_`, and `\` as literal characters. SQLite's `LIKE` comparison
is case-insensitive for ASCII text by default. Blank searches show the normal
paginated list.

Each import is a transaction, so a failed request leaves the previous cache
intact. The task only imports newer additions: deletions on Bluesky are not
removed locally, and existing cached posts are not rechecked for later blocks or
deletion. A completed fetch is tracked separately so an empty collection does not
appear unfetched. Signing out keeps cached bookmarks in the local database.

Optional path overrides: `BOOKMARKS_DATABASE`, `AUTHPROTO_DATABASE`, and
`OAUTH_METADATA_PATH`. Defaults are the paths above, resolved relative to this app.

## Using the database from scripts

For scripts that only need ActiveRecord and the database, load `app/init.rb`:

```ruby
require_relative 'app/init'

account = Account.find_by!(did: 'did:plc:YOUR_ACCOUNT_DID')
account.bookmarks.newest_first.each do |bookmark|
  puts bookmark.text
end
```

This loads the models, database connection, and OAuth configuration without loading
`BookmarksApp`. Database rake tasks use the same initialization.

## Tests

```sh
bundle exec rspec
```

Tests use temporary SQLite databases and mocked API responses, with no live account.

See the upstream [bookmark response definitions](https://github.com/bluesky-social/indigo/blob/main/api/bsky/bookmarkdefs.go)
and [Sinatra ActiveRecord documentation](https://github.com/sinatra-activerecord/sinatra-activerecord).
