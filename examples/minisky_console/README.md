# Minisky OAuth console example

This is an example showing how to use an (experimental) OAuth client based on Minisky from the `irb` level, both locally and against the client metadata hosted on a production server. Both configurations are *public* clients.

Note: both variants receive and save the access tokens locally on your machine, and in both you perform requests using the received token locally in `irb`. The production server code only serves the JSON file and prints the callback params, it does not use the `AuthProto` library itself.


## Requirements

- Ruby 3.3+
- a domain name and an SSL certificate for your application for live deployment

## Setup

1. Clone the repository and navigate to the example app directory:

```bash
cd examples/minisky_console
```

2. Install dependencies:

```bash
bundle install
```

3. Generate an encryption key for encrypting session data:

```bash
openssl rand -base64 32

cat > .env
ATPROTO_MASTER_KEY=<value from above>
```


## Configuration

This example is configured to only use an SQLite storage using a database in `db/localhost_auth.sqlite3` or `db/production_auth.sqlite3`. The client metadata is hardcoded in the `localhost.rb` script for localhost, and in the `app.rb` mini-server for production.


## Localhost use

Run `bin/console`, then:

```rb
require_relative 'localhost'

client = create_client
authorize(client, 'your.handle')
```

This will print:

```
Open this URL in the browser and complete authorization:
https://....

Waiting for OAuth callback at http://127.0.0.1:9292/callback (Ctrl-C to cancel)
```

Open this URL and authorize the app. The example starts a temporary inline HTTP server on the specified port on localhost, which only receives the callback and calls the provided block, which completes the authorization. The script saves the session ID of the pending session in a local variable, and passes it back as `expected_session_id:` to the callback handling method in AuthProto for verification.

Once the browser redirects to the callback URL after your approval, the console should print:

```
Authentication complete ✓
Your session id: ......
```

Then, you can run `client.get_request(...)` and `client.post_request(...)` to perform authorized actions on the given account. By default, the example asks for permissions `repo:app.bsky.feed.post` and `rpc:app.bsky.feed.getTimeline?aud=*`, which allow calling `getTimeline` and creating/modifying posts. Try e.g.:

```rb
client.get_request('app.bsky.feed.getTimeline', { limit: 10 })
```

To restore a session after closing and reopening the console, write down the sesion ID printed after successful authentication, and then pass it back to the `OAuthClient` constructor:

```rb
client = create_client(session_id: '123456-789-abc-...')
```

The localhost script uses the `Minisky::OAuthClient.for_localhost` helper with the `REDIRECT_URI` and `SCOPE`
constants declared in `localhost.rb`. Keep those values unchanged when restoring a stored session, since they determine
the client ID, and a session may only be restored for the same client ID it was created for.


## Production use

Deploy the code in `examples/minisky_console` to a production server using a method of your choice. The relevant part is in the `app.rb` file.

Create an `.env` file in the app folder with:

```
SERVER_HOST=your.server.hostname
```

Locally, run `bin/console`, then:

```rb
require_relative 'production'

client = create_client('your.server.hostname')
authorize(client, 'your.handle')
```

This will print:

```
Open this URL in the browser and complete authorization:
https://....
```

Open this URL and authorize the app. Once the browser redirects to the callback URL after your approval, the page you get redirected to will print the received params.

Copy the printed command back to the console:

```rb
handle_callback(client, { ... })
```

This will print:

```
Authentication complete ✓
Your session id: ......
```

Then, you can run `client.get_request(...)` and `client.post_request(...)` to perform authorized actions on the given account.

Again, to restore a session after closing and reopening the console, write down the sesion ID printed after successful authentication, and then pass it back to the `OAuthClient` constructor:

```rb
client = create_client('your.server.hostname', session_id: '123456-789-abc-...')
```
