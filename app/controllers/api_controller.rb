class ApiController < ApplicationController
   http_basic_authenticate_with name:ENV["API_AUTH_NAME"], password:ENV["API_AUTH_PASSWORD"], :only => [:register_user, :signin, :get_token]  


  skip_before_filter  :verify_authenticity_token
  
  def register_user
    if params && params[:display_name] && params[:email] && params[:password]
        if  User.where(:email => params[:email]).first
           signin
           return
        end
        
        params[:user] = Hash.new    
        #params[:user][:first_name] = params[:full_name].split(" ").first
        #params[:user][:last_name] = params[:full_name].split(" ").last
        params[:user][:email] = params[:email]
        params[:user][:display_name] = params[:display_name] 
        begin 
          decrypted_pass = params[:password]   #AESCrypt.decrypt(params[:password], ENV["API_AUTH_PASSWORD"])
        rescue Exception => e
          decrypted_pass = nil          
        end
                
        params[:user][:password] = decrypted_pass  
        params[:user][:verification_code] = rand_string(20)
    
        user = User.new(user_params)
        if user.save
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
        render :json => e.to_json, :status => 400
      end
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
  
  def photo_params
    params.require(:photo).permit(:name, :title, :user_id, :random_id, :image_url)
  end

end
