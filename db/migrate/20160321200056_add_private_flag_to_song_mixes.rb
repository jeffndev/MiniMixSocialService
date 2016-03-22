class AddPrivateFlagToSongMixes < ActiveRecord::Migration
  def change
    add_column :song_mixes, :private_flag, :boolean, :default => false
  end
end
