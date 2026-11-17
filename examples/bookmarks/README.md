# Bluesky bookmarks example

This example project implements a simple webapp which lets the user authenticate with their Bluesky/ATProto account, and then imports their private Bluesky bookmarks to a local database and lets them browse and search them.


## Requirements

- Ruby 3.3+
- a domain name and an SSL certificate for your application for live deployment


## Setup

1. Clone the repository and navigate to the example app directory:

```bash
cd examples/bookmarks
```

2. Install dependencies:

```bash
bundle install
```


## App configuration

### Client metadata

An ATProto OAuth app needs to have a [Client Metadata JSON file](https://atproto.com/specs/oauth#client-id-metadata-document), which configures the app's security settings and some user-facing info. This JSON file is normally hosted at the `/oauth-client-metadata.json` path. This app includes such endpoint, and reads the contents of the JSON to serve there from a file at `config/oauth-client-metadata.json`.

The configuration differs for localhost testing and a production site:

For localhost testing:

- Create a metadata file from the included **<u>localhost</u>** example:
    ```bash
    cp config/oauth-client-metadata.localhost.json config/oauth-client-metadata.json
    ```
    Here, this file is only used by the app to read the redirect URI and scope from there – it's not accessed by the authorization server.

For a live version:

- Create a metadata file from the included **<u>production</u>** example:
    ```bash
    cp config/oauth-client-metadata.production.json config/oauth-client-metadata.json
    ```
- Replace the `YOUR_DOMAIN_HERE` in the URLs with the hostname where your app will be hosted
- If you want to use the app as a confidential client, generate the signing keys for client authentication (client assertions):
    ```bash
    bundle exec ruby scripts/generate_keys.rb
    ```
    and copy the private and public keys to `config/keys.json` and `config/oauth-client-metadata.json` respectively.
- Otherwise, if you want to run it as a public client:
  - change `token_endpoint_auth_method` in the metadata JSON to `"none"`
  - remove the `token_endpoint_auth_signing_alg` line
  - remove the `jwks` section


### ENV vars

Apart from the `oauth-client-metadata.json` & `keys.json` files, the app is configured through ENV variables. You can set them through `export` on the command line, but it also has [dotenv](https://github.com/bkeepers/dotenv) set up, so you can put the config vars in a file named `.env`.

You will need to generate session & encryption keys first. You can do it like this:

```bash
openssl rand -base64 32
openssl rand -hex 32

cat > .env
ATPROTO_MASTER_KEY=<base64 value from first command>
SESSION_SECRET=<hex value from second command>
```

`ATPROTO_MASTER_KEY` is used by AuthProto to encrypt some of the stored session/nonce data in the configured storage; `SESSION_SECRET` is used by `Rack::Session::Cookie` for the browser session.


### Storage

Storage configuration is not needed here – this app has a hardcoded SQLite storage for AuthProto. The token, session and nonce data is stored in `db/authproto.sqlite3`.

The app also has a second SQLite database for the app's actual data – the imported bookmarks, account settings, and import info. This database (with `accounts`, `bookmarks`, and `sessions` tables) is stored in `db/bookmarks.sqlite3` and managed by ActiveRecord.

Before starting the app, you need to initialize this database by running the migration:

```sh
bundle exec rake db:migrate
```

The [sinatra-activerecord gem](https://github.com/sinatra-activerecord/sinatra-activerecord) is used for some integration of ActiveRecord with the server & rake tasks in a non-Rails environment.


## Running on localhost

```sh
bundle exec rackup
```

Open <http://127.0.0.1:9292> in the browser and sign in using your handle, then click on the "Fetch your bookmarks" link. You should then see a paginated list of your bookmarks with a search form (for simplicity, only post text is displayed, without images or other embeds, and posts with no text are skipped).


## Live deployment

```bash
RACK_ENV=production bundle exec rackup
```

This will start the server on `http://localhost:9292`. For a live deployment, the application must be accessible from the Internet for OAuth to work – the Authorization Server (PDS or entryway) needs to be able to load your `oauth-client-metadata.json` file before you can start the OAuth flow – so you will need to configure e.g. Nginx or Caddy to route requests from a given domain to your app, or use something like Passenger inside Nginx/Apache.

You will also need to set the `PERMITTED_DOMAIN` env var to the domain you run the app on. This is passed to the [:host_authorization](https://sinatrarb.com/intro.html#available-settings) option in Sinatra, which uses it to configure the [Rack::Protection::HostAuthorization](https://github.com/sinatra/sinatra/blob/main/rack-protection/lib/rack/protection/host_authorization.rb) middleware.

    PERMITTED_DOMAIN=your.domain.com

Remember to also set that domain in the URLs in `oauth-client-metadata.json` under `client_id` & `redirect_uris`.

You can also use e.g. Tailscale funnels or Cloudflare tunnels to make an app on a local machine available from outside, see the instructions in the [basic_webapp's readme](../basic_webapp#tailscale).


## How the app works

The main app code is spread across a few files in the `app` directory:

- `oauth.rb` – some global configuration for OAuth and AuthProto, accessed as a singleton from other parts
- `init.rb` – an initializer setting everything up
- `server.rb` – the main Sinatra server code
- `account.rb`, `bookmark.rb` and `session.rb` – ActiveRecord models
- `bookmark_sync.rb` – the background import and OAuth session cleanup task

There's a Rakefile with a rake task for updating a given account's import, which could be run e.g. from crontab. The Rakefile only needs to include the initializer code, but can skip the `server.rb` part.


### OAuth Authorization

The app uses both `AuthProto::Client` and `Minisky::OAuth` in different parts.

`Minisky::OAuth` is designed to be a stateful client, tracking a specific session of a specific user. This is not necessarily the best tool for a stateless webapp server controller, where each entry into an endpoint should look up the relevant user session from scratch (since there could be multiple users using the app in parallel). `AuthProto::Client` does not store session references in instance variables – session ID is always passed when needed in the argument to specific methods.

So the `server.rb` uses a plain `AuthProto::Client`; the `oauth.rb` file makes one available as a global singleton object as `OAuth.client`. `/authenticate` and `/callback` call `#authorize` and `#handle_callback` on it respectively in order to start and complete the authorization flow. Pending session ID and then authorized session ID is stored in the browser session, and then used to look up session info for authenticated user using the `#current_session` helper.

When completing authorization, the server also uses [didkit](https://tangled.org/mackuba.eu/didkit) to look up the authorized user's handle from their DID document, to display it later in the header.

The app only requests the `rpc:app.bsky.bookmark.getBookmarks?aud=*` permission, so it can't modify or access any of your other data, or even modify bookmarks, it only has read-only access to them (the `*` is so that you can use alternative AppViews like Blacksky's or Eurosky's). It's generally a good idea to use [granular OAuth permissions](https://atproto.com/guides/permission-requests) in your ATProto apps, requesting only what your app will actually need – this makes it easier for the users to trust your app.


### Session handling

The `sessions` table in `bookmarks.db` database stores a list of session IDs of AuthProto sessions (just the IDs, without the token info) linked n-to-1 to specific accounts in the `accounts` table. The reason for this is that we want to be able to track all sessions of a given user in order to use their tokens for background import (see below), and the `AuthProto::Storage` is just a key-value store that doesn't expose any querying by field. So when a session completes authorization, its ID is added to this table. There might be more than one active session for a given user, if they e.g. have logged in on multiple devices.

When the user logs out, we *don't* delete or revoke the session, but we only mark its `active` boolean flag as `false`. This means the session is no longer used (and won't ever be used again) by the user to access things while browsing the site, but can still be used by our cron jobs or background workers for some background syncing operations. We need this because we need at least one working session with access tokens to make requests to Bluesky's API to sync bookmarks, if we want to do this periodically e.g. once a day, and we need this to work even if the user has logged out from their browser. When checking authentication in the controller's helpers, we also look up if the session exists in the `sessions` table and if it's not logged out (in case e.g. an old browser cookie gets restored somehow).

When a background sync operation runs (`app/bookmark_sync.rb`), we pick the newest "active" session or a newest logged-out session if there are no active ones, and use its access tokens to connect. We also clean up (delete locally & revoke remotely) all older logged-out sessions except the currently used one – we only need one of those, and the old ones shouldn't be kept forever.


### The import

The bookmark import (`Bookmark.fetch_bookmarks`) is launched in the `/fetch` endpoint when the user clicks "Fetch your bookmarks", and can also be run from the rake task `rake bookmarks:fetch`.

For simplicity, the import runs synchronously inside the controller, and everything is rendered server-side with ERB HTML output. In a real app, you'd rather want to perform such import instead inside a background worker process run with something like [Sidekiq](https://github.com/sidekiq/sidekiq), and possibly use JavaScript fetch requests for a more responsive UI.

The import process uses `Minisky::OAuth` for a bit more high-level XRPC request API. `Minisky::OAuth` has a convenience initializer `with_oauth_client`, which you can use to pass it an existing `AuthProto::Client` instance to work with underneath – in this case we pass the same global OAuth client as before:

```rb
sky = Minisky::OAuth.with_oauth_client(OAuth.client, session_id: session_id)
```

The import uses Minisky's `#fetch_all` helper to make requests to `app.bsky.bookmark.getBookmarks` in a loop, updating the cursor and collecting the entries from each page into one result array. The block passed to the `break_when:` parameter tells it to stop when it reaches the newest previously downloaded bookmark. When the fetch completes, the newly fetched bookmarks are saved inside a transaction.

The call goes to the user's PDS, since that's what we have the access token for, but the data we want to fetch is actually on the AppView. This is solved using [XRPC service proxying](https://atproto.com/specs/xrpc#service-proxying), where we call the PDS but use an `atproto-proxy` header to specify where it should proxy the request to:

```rb
headers = { 'atproto-proxy' => 'did:web:api.bsky.app#bsky_appview' }
...
entries = sky.fetch_all('app.bsky.bookmark.getBookmarks', { limit: 100 },
                        field: 'bookmarks', break_when: ->(x) { ... }, headers: headers)
```

We also give the user the option to turn the background sync on and off. If it's off, the cron job running the sync task will skip the import and only clean up older sessions (and if only inactive sessions are left, it will remove them all, so at this point the app will no longer own any access tokens to access the user's account again).

