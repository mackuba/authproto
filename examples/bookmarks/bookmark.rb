# frozen_string_literal: true

require 'active_record'

require_relative 'init'

class Bookmark < ActiveRecord::Base
  # Keep the API's bookmark timestamp instead of ActiveRecord's insertion time.
  self.record_timestamps = false

  scope :newest_first, -> { order(created_at: :desc, uri: :desc) }

  # Returns the Bluesky post URL using the author DID and record key in its AT URI.
  #
  # @return [String] public post URL
  #
  def post_url
    did, rkey = uri.delete_prefix('at://').split('/').values_at(0, 2)

    "https://bsky.app/profile/#{did}/post/#{rkey}"
  end
end
