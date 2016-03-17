class CreateSongMixes < ActiveRecord::Migration
  def change
    create_table :song_mixes do |t|
      t.string :name
      t.string :song_identifier_hash
      t.string :genre
      t.string :song_description
      t.float :self_rating
      t.float :song_duration_secs
      t.string :mix_file_url
      t.string :s3_random_id
      t.integer :user_id 
      t.timestamps null: false
    end
  end
end
