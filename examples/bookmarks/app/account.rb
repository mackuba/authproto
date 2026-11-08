# frozen_string_literal: true

require 'active_record'

require_relative 'init'


#
# A bookmark owner and the state of their most recent OAuth login and import.
#

class Account < ActiveRecord::Base
  has_many :bookmarks, dependent: :destroy

  validates :did, presence: true
end
