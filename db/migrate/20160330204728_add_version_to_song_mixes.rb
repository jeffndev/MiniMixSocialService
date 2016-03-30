class AddVersionToSongMixes < ActiveRecord::Migration
  def change
    add_column :song_mixes, :version, :integer, :default => 0, :null => false
  end
end
