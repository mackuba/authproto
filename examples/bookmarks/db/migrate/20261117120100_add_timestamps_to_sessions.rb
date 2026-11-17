# frozen_string_literal: true

class AddTimestampsToSessions < ActiveRecord::Migration[8.1]
  def up
    add_timestamps :sessions, null: true

    execute <<~SQL
      UPDATE sessions SET created_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
    SQL

    change_column_null :sessions, :created_at, false
    change_column_null :sessions, :updated_at, false
  end

  def down
    remove_timestamps :sessions
  end
end
