# frozen_string_literal: true

class CreateBookmarks < ActiveRecord::Migration[8.1]
  def change
    create_table :accounts do |t|
      t.string :did, null: false
      t.boolean :fetched, default: false, null: false
      t.string :session_id
    end

    add_index :accounts, :did, unique: true

    create_table :bookmarks do |t|
      t.string :uri, null: false
      t.string :author_handle, null: false
      t.datetime :created_at
      t.datetime :posted_at, null: false
      t.text :text, null: false
      t.integer :account_id, null: false
    end

    add_index :bookmarks, [:account_id, :created_at], order: { created_at: :desc }
    add_index :bookmarks, [:account_id, :uri], unique: true

    add_foreign_key :bookmarks, :accounts
  end
end
