# frozen_string_literal: true

require 'active_record'
require 'time'

require_relative 'init'
require_relative 'account'

class Bookmark < ActiveRecord::Base
  belongs_to :account

  # Keep the API's bookmark timestamp instead of ActiveRecord's insertion time.
  self.record_timestamps = false

  scope :newest_first, -> { order(created_at: :desc, uri: :desc) }

  # Fetches bookmarks synchronously, following API cursors and saving text posts.
  # Saves the results atomically after fetching so an incremental retry cannot miss older pages.
  #
  # @param session_id [String] OAuth session belonging to the bookmark owner
  # @param newer_only [Boolean] stop at the newest locally saved bookmark
  # @return [Integer] number of imported bookmarks
  # @raise [Minisky::AuthError] if the session cannot be resumed
  #
  def self.fetch_bookmarks(session_id, newer_only: false)
    sky = Minisky::OAuth.with_oauth_client(OAuth.client, session_id: session_id)
    sky.check_access

    account = Account.find_by!(did: sky.did)

    newest = account.bookmarks.maximum(:created_at) if newer_only

    entries = sky.fetch_all('app.bsky.bookmark.getBookmarks', { limit: 100 },
      field: 'bookmarks',
      headers: {
        'atproto-proxy' => 'did:web:api.bsky.app#bsky_appview'
      },
      break_when: newest && lambda { |entry|
        created_at = entry['createdAt']
        created_at && Time.iso8601(created_at) <= newest
      }
    )

    imported = 0

    transaction do
      entries.each do |entry|
        post = entry.fetch('item')
        next unless post['$type'] == 'app.bsky.feed.defs#postView'

        record = post.fetch('record')
        next if record['text'].blank?

        uri = entry.fetch('subject').fetch('uri')
        created_at = entry['createdAt']

        bookmark = account.bookmarks.find_or_initialize_by(uri: uri)

        bookmark.update!(
          author_handle: post.fetch('author').fetch('handle'),
          created_at: created_at && Time.iso8601(created_at),
          posted_at: Time.iso8601(record.fetch('createdAt')),
          text: record.fetch('text')
        )

        imported += 1
      end

      account.update!(fetched: true)
    end

    imported
  end

  # Returns the Bluesky post URL using the author DID and record key in its AT URI.
  #
  # @return [String] public post URL
  #
  def post_url
    did, rkey = uri.delete_prefix('at://').split('/').values_at(0, 2)

    "https://bsky.app/profile/#{did}/post/#{rkey}"
  end
end
