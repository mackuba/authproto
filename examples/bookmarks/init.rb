# frozen_string_literal: true

require 'authproto'
require 'authproto/minisky'
require 'didkit'
require 'dotenv/load'
require 'sinatra/activerecord'

AuthProto.configure do |config|
  config.http_client = AuthProto::HTTPClient.new(timeout: 10)

  config.storage = AuthProto::Storage::SQLite.new(
    path: ENV.fetch('AUTHPROTO_DATABASE', File.join(__dir__, 'db', 'authproto.sqlite3'))
  )
end

Sinatra::Base.register(Sinatra::ActiveRecordExtension)
Sinatra::Base.set(:database, {
  adapter: 'sqlite3',
  database: ENV.fetch('BOOKMARKS_DATABASE', File.join(__dir__, 'db', 'bookmarks.sqlite3')),
  timeout: 5_000
})
