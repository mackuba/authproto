# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_11_07_004141) do
  create_table "accounts", force: :cascade do |t|
    t.string "did", null: false
    t.boolean "fetched", default: false, null: false
    t.string "session_id"
    t.index ["did"], name: "index_accounts_on_did", unique: true
  end

  create_table "bookmarks", force: :cascade do |t|
    t.string "uri", null: false
    t.string "author_handle", null: false
    t.datetime "created_at"
    t.datetime "posted_at", null: false
    t.text "text", null: false
    t.integer "account_id", null: false
    t.index ["account_id", "created_at"], name: "index_bookmarks_on_account_id_and_created_at", order: { created_at: :desc }
    t.index ["account_id", "uri"], name: "index_bookmarks_on_account_id_and_uri", unique: true
  end

  add_foreign_key "bookmarks", "accounts"
end
