class SongMix < ActiveRecord::Base
  belongs_to :user
  has_many :audio_tracks  


  def to_json(options={})
    options[:except] ||= [:id, :user_id, :created_at, :updated_at]
    super(options)
  end  
end
