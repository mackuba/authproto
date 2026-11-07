# frozen_string_literal: true


#
# Creates the local cache of private bookmarks, shared by all signed-in accounts.
#

class CreateBookmarks < ActiveRecord::Migration[8.1]
  def change
    create_table :bookmarks do |t|
      t.string :did, null: false
      t.string :uri, null: false
      t.string :author_handle, null: false
      t.datetime :created_at, precision: 6
      t.datetime :posted_at, null: false, precision: 6
      t.text :text, null: false
    end

    add_index :bookmarks, [:did, :created_at], order: { created_at: :desc }
    add_index :bookmarks, [:did, :uri], unique: true
  end
end
