class AudioTrack < ActiveRecord::Base
  belongs_to :song_mix

  def to_json(options={})
    options[:except] ||= [:id, :song_mix_id, :created_at, :updated_at]
    super(options)
  end  
end
