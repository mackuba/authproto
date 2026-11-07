# frozen_string_literal: true

require 'active_record'

require_relative 'init'

class Bookmark < ActiveRecord::Base
  # Keep the API's bookmark timestamp instead of ActiveRecord's insertion time.
  self.record_timestamps = false

  scope :newest_first, -> { order(created_at: :desc, uri: :desc) }

  # Fetches bookmarks synchronously, following API cursors and saving text posts.
  # A failed fetch rolls back the import so an incremental retry cannot miss older pages.
  #
  # @param session_id [String] OAuth session belonging to the bookmark owner
  # @param newer_only [Boolean] stop at the newest locally saved bookmark
  # @return [Integer] number of imported bookmarks
  # @raise [Minisky::AuthError] if the session cannot be resumed
  #
  def self.fetch_bookmarks(session_id, newer_only: false)
    client = Minisky::OAuthClient.with_oauth_client(OAuth.client, session_id: session_id)
    client.check_access

    did = client.did

    newest = Bookmark.where(did: did).maximum(:created_at) if newer_only
    imported = 0
    cursor = nil

    headers = { 'atproto-proxy' => 'did:web:api.bsky.app#bsky_appview' }

    Bookmark.transaction do
      loop do
        query = { limit: 100 }
        query[:cursor] = cursor if cursor

        response = client.get_request('app.bsky.bookmark.getBookmarks', query, headers: headers)
        reached_newest = false

        response.fetch('bookmarks').each do |entry|
          created_at = entry['createdAt'] && Time.iso8601(entry['createdAt'])

          if newest && created_at && created_at <= newest
            reached_newest = true
            next
          end

          post = entry.fetch('item')
          next unless post['$type'] == 'app.bsky.feed.defs#postView'

          record = post.fetch('record')
          next if record['text'].blank?

          bookmark = Bookmark.find_or_initialize_by(did: did, uri: entry.fetch('subject').fetch('uri'))
          bookmark.update!(
            author_handle: post.fetch('author').fetch('handle'),
            created_at: created_at,
            posted_at: Time.iso8601(record.fetch('createdAt')),
            text: record.fetch('text')
          )

          imported += 1
        end

        cursor = response['cursor']
        break if cursor.blank? || reached_newest
      end
    end

    AuthProto.storage.set("atproto:bookmarks:fetched:#{did}", 'true')
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
