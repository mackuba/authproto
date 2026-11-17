# frozen_string_literal: true

require_relative 'bookmark'
require_relative 'session'


#
# Runs an incremental import and cleans up signed-out OAuth sessions.
#

class BookmarkSync
  def initialize(account)
    @account = account
  end

  def run
    used_session = nil
    fetched_bookmarks = nil

    if @account.sync_enabled?
      used_session, fetched_bookmarks = fetch_bookmarks
    end

    cleanup_sessions(except: used_session)
    fetched_bookmarks
  end


  private

  def fetch_bookmarks
    # We need one set of working access tokens for the user's account to run the import.
    # Loop over the user's all sessions and find the first one that works.

    @account.sessions.order(active: :desc, id: :desc).each do |session|
      begin
        count = Bookmark.fetch_bookmarks(session.session_id, newer_only: true)
        return [session, count]
      rescue Minisky::AuthError
        next
      rescue AuthProto::Token::RefreshError => error
        raise unless error.message.start_with?('Refresh token has been invalidated: invalid_grant')
      end
    end

    raise Minisky::AuthError, "No usable OAuth session for #{@account.did}. Sign in through the web app first."
  end

  def cleanup_sessions(except: nil)
    @account.sessions.inactive.each do |session|
      next if session.session_id == except&.session_id
      OAuth.client.delete_session(session.session_id, revoke: true)
      session.destroy!
    end
  end
end
