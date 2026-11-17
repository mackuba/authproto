# frozen_string_literal: true

require 'active_record'


#
# Links an Account to an AuthProto session (from the configured AuthProto session storage) through its `session_id`
# identifier. When the user logs out, the session is marked as inactive and not used for website access anymore,
# but it's kept temporarily in the session storage & database in order to allow background access for the bookmark
# import job while the user isn't logged in.
#
# Logged-out sessions are cleaned up eventually, although one remaining session is always kept to allow background
# sync, unless the user disables the syncing.
#

class Session < ActiveRecord::Base
  belongs_to :account

  scope :active, -> { where(active: true) }
  scope :inactive, -> { where(active: false) }
end
