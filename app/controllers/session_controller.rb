class SessionController < ApplicationController
  def new
  end

  def create
    @user = User.find_by(name: params[:session][:name].downcase)
    if @user && @user.authenticate(params[:session][:password])
      log_in @user
      response = HTTParty.get("http://#{WebClient::Application::SERVER_IP}/#{@user.name}")
      puts "============================================"
      puts "Status Code: #{response["status"]}"
      puts "============================================"
      if response["status"].to_s == "111"

        #erzeugen des masterkeys
        iter = 10000
        digest = OpenSSL::Digest::SHA256.new
        masterkey = OpenSSL::PKCS5.pbkdf2_hmac(params[:session][:password], response["salt_masterkey"], iter, 256, digest)
        #entschlüsseln des privkey_user_enc zu priv_key_user
        privkey_user_enc_base = Base64.decode64(response["privkey_user_enc"])

        decipher = OpenSSL::Cipher::AES.new(128, :ECB)
        decipher.decrypt
        decipher.key = masterkey

        privkey_user_enc = decipher.update(privkey_user_enc_base) + decipher.final
        $privkey_user = OpenSSL::PKey::RSA.new(privkey_user_enc, masterkey)

        puts "============================================"
        puts "User logged in and Session created"
        puts "============================================"
        redirect_to messages_url
      else
        render 'new'
      end


    else
      # Create an error message.
      flash[:danger] = 'Invalid email/password combination'
      render 'new'
    end
  end

  def delete
    log_out
    redirect_to root_url
  end
end
