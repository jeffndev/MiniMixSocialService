class ApiController < ApplicationController
   http_basic_authenticate_with name:ENV["API_AUTH_NAME"], password:ENV["API_AUTH_PASSWORD"], :only => [:register_user, :signin, :get_token]
   before_filter :check_for_valid_authtoken, :except => [ :register_user, :signin, :get_token ]  


  skip_before_filter  :verify_authenticity_token
  
  def register_user
    if params && params[:display_name] && params[:email] && params[:password]
        if  User.where(:email => params[:email]).first
           signin
           return
        end
        if User.where(:display_name => params[:display_name]).first
          e = Error.new(:status => 400, :message => "user display name is taken, please choose another one")
          render :json => e.to_json, :status => 410 and return
        end        
        params[:user] = Hash.new    
        params[:user][:email] = params[:email]
        params[:user][:display_name] = params[:display_name] 
        begin 
          decrypted_pass = AESCrypt.decrypt(params[:password], ENV["API_AUTH_PASSWORD"])
        rescue Exception => e
          decrypted_pass = nil          
        end
                
        params[:user][:password] = decrypted_pass  
        params[:user][:verification_code] = rand_string(20)
    
        user = User.new(user_params)
        if user.save
           if !user.api_authtoken || (user.api_authtoken && user.authtoken_expiry < Time.now)
             auth_token = rand_string(20)
             auth_expiry = Time.now + (24*60*60)
          
             user.update_attributes(:api_authtoken => auth_token, :authtoken_expiry => auth_expiry)    
           end
           render :json => user.to_json, :status => 200
        else
          puts 'SAVE FAILED...'
          error_str = ""

          user.errors.each{|attr, msg|           
            error_str += "#{attr} - #{msg},"
          }
          puts error_str
          
          e = Error.new(:status => 400, :message => error_str)
          render :json => e.to_json, :status => 400
        end
      else
        e = Error.new(:status => 400, :message => "required parameters are missing")
        render :json => e.to_json, :status => 420
      end
  end

  def verify_token
    if !@user
      e = Error.new(status: 401, message: 'User token could not identify user')
      render json: e.to_json, status: 401 and return
    end
    verify = { verify_info: { valid: @user.authtoken_expiry > Time.now }} 
    render json: verify.to_json, status: 200
  end  

  def song_privacy
    if !@user
      e = Error.new(status: 401, message: 'User token could not identify user')
      render json: e.to_json, status: 401 and return
    end
    if !params[:song_id]
      e = Error.new( status: 400, message: 'required parameters are missing')
      render json: e.to_json, status: 400 and return
    end
    if @user.authtoken_expiry < Time.now
      e = Error.new( status: 401,  message: 'User authtoken has expired, could not identify user')
      render json: e.to_json, status: 400 and return
    end
    song = SongMix.where( song_identifier_hash: params[:song_id] ).first
    if !song
      e = Error.new( status: 400, message: 'could not identify song from id')
      render json: e.to_json, status: 400 and return
    end
    verify = { song_info: { private_flag: song.private_flag }} 
    render json: verify.to_json, status: 200
  end

  def signin
    if request.post?
      if params && params[:email] && params[:password]
        user = User.where(:email => params[:email]).first
                      
        if user 
          if User.authenticate(params[:email], params[:password]) 
                    
            if !user.api_authtoken || (user.api_authtoken && user.authtoken_expiry < Time.now)
              auth_token = rand_string(20)
              auth_expiry = Time.now + (24*60*60)
          
              user.update_attributes(:api_authtoken => auth_token, :authtoken_expiry => auth_expiry)    
            end 
                                   
            render :json => user.to_json, :status => 200
          else
            e = Error.new(:status => 401, :message => "Wrong Password")
            render :json => e.to_json, :status => 401
          end      
        else
          e = Error.new(:status => 400, :message => "No USER found by this email ID")
          render :json => e.to_json, :status => 400
        end
      else
        e = Error.new(:status => 400, :message => "required parameters are missing")
        render :json => e.to_json, :status => 400
      end
    end
  end
  def upload_track_file
    if  params[:song_identifier_hash] && params[:track_identifier_hash] && params[:track] 
      #user = User.where( :email => params[:email]).first
      if !@user
        e = Error.new( status: 401, message: 'Could not identify the user')
        render json: track.to_json and return  
      end
      if @user.authtoken_expiry > Time.now
        song = @user.song_mixes.where( :song_identifier_hash => params[:song_identifier_hash]).first
        if song.nil?
           e = Error.new(:status => 400, :message => 'Could not identify the song for file upload')
           render :json => e.to_json, :status => 400 and return
        end
        track = song.audio_tracks.where( :track_identifier_hash => params[:track_identifier_hash]).first
        if track.nil?
            e = Error.new(:status => 400, :message => 'Could not identify the track for file upload')
           render :json => e.to_json, :status => 400 and return
        end
        #TODO: will have to deal with versions at some point, so this will change..
        if !track.track_file_url.blank? && !track.s3_random_id.blank?
           puts "track file was already uploaded"
           render :json => track.to_json  and return
        end
        track_file = params[:track].read
        
        s3 = AWS::S3.new
        if s3
          rand_id = rand_string(40)
          bucket = s3.buckets[ENV["S3_BUCKET_NAME"]]
          s3_obj = bucket.objects[rand_id]
          s3_obj.write(track_file, :acl => :public_read)
          audio_file_url = s3_obj.public_url.to_s
          
          if track.update_attributes( :track_file_url => audio_file_url, :s3_random_id => rand_id)
              render :json => track.to_json and return
          else
              error_str = ""

              track.errors.each{|attr, msg|           
                error_str += "#{attr} - #{msg},"
              }
                    
              e = Error.new(:status => 400, :message => error_str)
              render :json => e.to_json, :status => 400
          end
        else
          e = Error.new(:status => 400, :message => 'Could not connect to AWS S3')
          render :json => e.to_json, :status => 400
        end
      else
        e = Error.new(:status => 401, :message => 'User authtoken has expired, could not identify user')
        render :json => e.to_json, :status => 400  
      end
    else
      e = Error.new(:status => 400, :message => 'required upload form parameters were not there')
      render :json => e.to_json, :status => 400
    end
  end
 
  def search_songs
    if !params[:query]
       e = Error.new(:status => 400, :message => 'required search form parameters were not there')
      render :json => e.to_json, :status => 400 and return
    end
    #TODO: looking up the user each time will reallly slow things, would like to avoid this...maybe cache it somehow
    #user = User.where( email: params[:email]).first
    if !@user
        e = Error.new( status: 401, message: 'Could not identify the user')
        render json: track.to_json and return  
     end
    if @user.authtoken_expiry < Time.now
      e = Error.new(:status => 401, :message => 'User authtoken has expired, could not identify user')
      render :json => e.to_json, :status => 400 and return
    end
    query = params[:query]
    toks =  query.strip.split(/\W+/)
    tsquery = toks.join('|')
    #TODO: now put that query into the textsearch through psql..
    render :json => Search.advanced_search(term: tsquery).where("user_id != ?", @user.id).limit(20).to_json( except: [:term, :searchable_type] ), :status => 200
  end
 
  def upload_song_file
    if  params[:song_identifier_hash] && params[:mix] 
      #user = User.where( :email => params[:email]).first
      if !@user
        e = Error.new( status: 401, message: 'Could not identify the user')
        render json: track.to_json and return  
      end
      if @user.authtoken_expiry > Time.now
        puts "in upload, got user"
        song = @user.song_mixes.where( :song_identifier_hash => params[:song_identifier_hash]).first
        if song.nil?
           e = Error.new(:status => 400, :message => 'Could not identify the song for file upload')
           render :json => e.to_json, :status => 400 and return
        end
        #TODO: might want to check if exists s3_random_id and mix_file_url already...
        #puts song.mix_file_url
        #puts song.s3_random_id
        if !song.mix_file_url.blank? && !song.s3_random_id.blank?
           puts "song file was already uploaded"
           render :json => song.to_json(:include => { :audio_tracks => { :except => [:created_at, :updated_at, :id, :song_mix_id] }}) and return
        end
        song_file = params[:mix].read
        
        s3 = AWS::S3.new
        if s3
          rand_id = rand_string(40)
          bucket = s3.buckets[ENV["S3_BUCKET_NAME"]]
          s3_obj = bucket.objects[rand_id]
          s3_obj.write(song_file, :acl => :public_read)
          audio_file_url = s3_obj.public_url.to_s
          
          if song.update_attributes( :mix_file_url => audio_file_url, :s3_random_id => rand_id)
              render :json => song.to_json(:include => { :audio_tracks => { :except => [:created_at, :updated_at, :id, :song_mix_id] }})
          else
              error_str = ""

              song.errors.each{|attr, msg|           
                error_str += "#{attr} - #{msg},"
              }
                    
              e = Error.new(:status => 400, :message => error_str)
              render :json => e.to_json, :status => 400
          end
        else
          e = Error.new(:status => 400, :message => 'Could not connect to AWS S3')
          render :json => e.to_json, :status => 400
        end
      else
        e = Error.new(:status => 401, :message => 'User authtoken has expired, could not identify user')
        render :json => e.to_json, :status => 401  
      end
    else
      e = Error.new(:status => 400, :message => 'required upload form parameters were not there')
      render :json => e.to_json, :status => 400
    end
  end
 
   def upload_song
    if params[:song_identifier_hash] && params[:name] && params[:genre] && params[:private_flag]
      #user = User.where( :email => params[:email]).first
       if !@user
        e = Error.new( status: 401, message: 'Could not identify the user')
        render json: track.to_json and return  
      end
      if @user.authtoken_expiry > Time.now
        old_song = SongMix.where( :song_identifier_hash => params[:song_identifier_hash]).first
        if old_song
         #TODO: check a version number, if params version is greater, then continue and remove old song from s3..
          render :json => old_song.to_json(:include => { :audio_tracks => { :except => [:created_at, :updated_at, :id, :song_mix_id] }})  and return
        end
        
          song = @user.song_mixes.build(
                             :name => params[:name],
                             :song_identifier_hash => params[:song_identifier_hash], 
                             :genre => params[:genre],
                             :song_description => params[:song_description], 
                             :self_rating => params[:self_rating],
                             :private_flag => params[:private_flag],
                             :song_duration_secs => params[:song_duration_secs])
          
          if song.save
              0.upto(5) do |i|
                break if !params["track_identifier_hash#{i}"]
                song.audio_tracks.create(:name => params["name#{i}"],
                                         :display_order => params["display_order#{i}"],
                                         :mix_volume => params["mix_volume#{i}"],
                                         :track_identifier_hash => params["track_identifier_hash#{i}"],
                                         :track_description => params["track_description#{i}"],
                                         :track_duration_secs => params["track_duration_secs#{i}"]
                                        )      
              end

              render :json => song.to_json(:include => { :audio_tracks => { :except => [:created_at, :updated_at, :id, :song_mix_id] }})
            else
              error_str = ""

              song.errors.each{|attr, msg|           
                error_str += "#{attr} - #{msg},"
              }
                    
              e = Error.new(:status => 400, :message => error_str)
              render :json => e.to_json, :status => 400
            end

      else
        e = Error.new(:status => 401, :message => 'User authtoken has expired, could not identify user')
        render :json => e.to_json, :status => 401  
      end
    else
      e = Error.new(:status => 400, :message => 'required upload form parameters were not there')
      render :json => e.to_json, :status => 400
    end
  end

private 
  
  def check_for_valid_authtoken
    authenticate_or_request_with_http_token do |token, options|     
      @user = User.where(:api_authtoken => token).first      
    end
  end
  
  def rand_string(len)
    o =  [('a'..'z'),('A'..'Z')].map{|i| i.to_a}.flatten
    string  =  (0..len).map{ o[rand(o.length)]  }.join

    return string
  end
  
  def user_params
    params.require(:user).permit(:display_name, :email, :password, :password_hash, :password_salt, :verification_code, 
    :email_verification, :api_authtoken, :authtoken_expiry)
  end
  
  #def photo_params
  #  params.require(:photo).permit(:name, :title, :user_id, :random_id, :image_url)
  #end

end
