# frozen_string_literal: true

class AddSessions < ActiveRecord::Migration[8.1]
  def up
    add_column :accounts, :sync_enabled, :boolean, default: true, null: false

    create_table :sessions do |t|
      t.references :account, null: false, foreign_key: true
      t.string :session_id, null: false
      t.boolean :active, default: true, null: false
      t.index :session_id, unique: true
    end

    execute <<~SQL
      INSERT INTO sessions (account_id, session_id)
      SELECT id, session_id FROM accounts WHERE session_id IS NOT NULL
    SQL

    remove_column :accounts, :session_id
  end

  def down
    add_column :accounts, :session_id, :string

    execute <<~SQL
      UPDATE accounts SET session_id = (
        SELECT session_id FROM sessions
        WHERE account_id = accounts.id AND active
        ORDER BY id DESC LIMIT 1
      )
    SQL

    drop_table :sessions
    remove_column :accounts, :sync_enabled
  end
end
