class CreateAudioTracks < ActiveRecord::Migration
  def change
    create_table :audio_tracks do |t|
      t.string :name
      t.string :track_description
      t.integer :display_order
      t.float :mix_volume
      t.float :track_duration_secs
      t.string :track_identifier_hash
      t.integer :song_mix_id
      t.string :track_file_url
      t.string :s3_random_id
      t.timestamps null: false
    end
  end
end
