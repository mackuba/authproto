# frozen_string_literal: true

require 'active_record'

require_relative 'init'


#
# A bookmark owner and the state of their bookmark import.
#

class Account < ActiveRecord::Base
  has_many :bookmarks, dependent: :destroy
  has_many :sessions, dependent: :destroy

  validates :did, presence: true
end
