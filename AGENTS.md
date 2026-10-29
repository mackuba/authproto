### Ruby code:

- always add `# frozen_string_literal: true` at the beginning of Ruby files (both library and tests)
- keep `require`s and `require_relative`s organized in separate blocks, ordered alphabetically in each:

```
require 'ipaddr'
require 'socket'
require 'timeout'
require 'uri'

require_relative 'client_metadata'
require_relative 'validated_uri'
```

- wrap lines longer than 120 characters
- for multi-line `if ... end` / `unless ... end` blocks, keep one empty line above/below separating them from the rest of the code in the method, unless it's at the beginning/end of the method, e.g.:

```
  def validate_grant_types(grant_types)
    unless grant_types.include?('authorization_code')
      raise InvalidClientMetadata, "grant_types must include authorization_code"
    end

    valid_types = %w[authorization_code refresh_token]
```

- prefer single-quote strings for strings containing identifiers without spaces, like `'code'`, `'access_token'`, and for `require`s
- prefer double-quote strings for strings containing messages with spaces meant to be shown to the user, e.g. `puts "grant_types must include authorization_code"`

### Unit tests:

- use the classic RSpec `foo.should be_...` matcher style instead of `expect()`
  - except for calling matchers on blocks as in `expect { ... }.to(not) raise_error...`
- use the classic `it "should do this"` naming for test cases instead of `it "does this"`
- use raw `describe` instead of `RSpec.describe` at the top level

### Documentation:

- use YARD with Markdown formatting
- for class comments, keep one empty # line at the beginning and end, and one empty line above and below that, like:

```

  #
  # OAuth client implementation class.
  #

  class ...
```

- for method comments, leave one empty line above, no empty # starting line, and one empty # trailing line that is immediately followed by the method definition, like:

```

  # Reads tokens for a session with a currently valid access token.
  #
  # @param session_id [String] session identifier
  # @return [Hash{Symbol => String, Integer, nil}, nil] token details, or `nil` for missing/unauthorized sessions
  #
  def get_tokens(session_id)
```

- for properties, and also for one-liner classes like error types, use a compact style like:

```

  # Identifier of the session associated with the failure, if known.
  # @return [String, nil]
  attr_reader :session_id

  # Error raised when token operations fail
  class TokenError < Error; end

```


### Running code:

- make sure you don't use the ancient system Ruby 2.6, but a version supported by the library (my installation uses `asdf`)
