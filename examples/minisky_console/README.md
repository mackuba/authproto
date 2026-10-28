# Minisky OAuth Console Example

This is an example showing how to do an (experimental) OAuth client based on Minisky from the `irb` level, both locally and against the client metadata hosted on a production server. Both configurations are *public* clients.

Note: both variants receive and save the access tokens locally on your machine, and in both you perform requests using the received token locally in `irb`. The production server code only serves the JSON file and prints the callback params, it does not use the `AuthProto` library itself.


## Requirements

- Ruby 3.3+
- Bundler
- A domain name for your application that matches your client metadata (required for production)
- SSL certificate for your domain (required for production)

## Setup

1. Clone the repository and navigate to the example directory:

```bash
cd examples/minisky_console
```

2. Install dependencies:

```bash
bundle install
```

3. Generate an encryption key:

```bash
openssl rand -base64 32

cat > .env
ATPROTO_MASTER_KEY=<value from above>
```


## Localhost use

Run `bin/console`, then:

```rb
require_relative 'localhost'

client = create_client('your.pds.hostname.here')
authorize(client)
```

This will print:

```
Open this URL in the browser and complete authorization:
https://....

Waiting for OAuth callback at http://127.0.0.1:9292/callback (Ctrl-C to cancel)
```

Open this URL and authorize the app. The example starts a temporary inline HTTP server on the specified port on localhost, which only receives the callback and calls the provided block, which completes the authorization.

Once the browser redirects to the callback URL after your approval, the console should print:

```
Authentication complete ✓
```

Then, you can run `client.get_request(...)` and `client.post_request(...)` to perform authorized actions on the given account. By default, the example asks for permissions `repo:app.bsky.feed.post` and `rpc:app.bsky.feed.getTimeline?aud=*`, which allow calling `getTimeline` and creating/modifying posts.

(Note, the session is currently lost when you close the console.)


## Production use

Deploy the code in `examples/minisky_console` to a production server using a method of your choice. The relevant part is in the `app.rb` file.

Create an `.env` file in the app folder with:

```
SERVER_HOST=your.server.hostname
```

Locally, run `bin/console`, then:

```rb
require_relative 'production'

client = create_client('your.server.hostname', 'your.pds.hostname')
authorize(client)
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
```

Then, you can run `client.get_request(...)` and `client.post_request(...)` to perform authorized actions on the given account.
