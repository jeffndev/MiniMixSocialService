class User < ActiveRecord::Base
  has_many :song_mixes
  validates_confirmation_of :password  
  validates_presence_of :email, :on => :create    
  validates :password, length: { in: 6..30 }, :on => :create 
  
  validates_format_of :email, :with => /\A[^@]+@([^@\.]+\.)+[^@\.]+\z/
  validates_uniqueness_of :email

 def self.authenticate(login_name, password)
    user = self.where("email =?", login_name).first
                   
    if user 
      puts "******************* #{password} 1"
      
     # begin
      #  password = AESCrypt.decrypt(password, ENV["API_AUTH_PASSWORD"])      
      #rescue Exception => e
      #  password = nil
      #  puts "error - #{e.message}"
      #end
      
     # puts "******************* #{password} 2"
              
      #if user.password_hash == BCrypt::Engine.hash_secret(password, user.password_salt)
      if user.password == password
        user
      else
        nil
      end
    else
      nil
    end
  end   


  def to_json(options={})
    options[:except] ||= [:id, :password, :password_hash, :password_salt, :email_verification, :verification_code, :created_at, :updated_at]
    super(options)
  end    
end
