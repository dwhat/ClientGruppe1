class UsersController < ApplicationController
  before_action :set_user, only: [:show, :edit, :update, :destroy]

  # GET /users
  # GET /users.json
  def index
    @users = User.all
  end

  # GET /users/1
  # GET /users/1.json
  def show
  end

  # GET /users/new
  def new
    @user = User.new
  end

  # GET /users/1/edit
  def edit
  end

  # POST /users
  # POST /users.json
  def create
    @user = User.new(user_params)

    #erzeugen des salts
    # salt_masterkey = OpenSSL::Random.random_bytes 64 anpassung!
    salt_masterkey = SecureRandom.hex(64).to_i.to_s
    puts salt_masterkey

    #erzeugen des masterkeys
    iter = 10000
    digest = OpenSSL::Digest::SHA256.new
    masterkey = OpenSSL::PKCS5.pbkdf2_hmac(user_params[:password], salt_masterkey, iter, 256, digest)

    #erzeugen des Schlüsselpaares
    keys = OpenSSL::PKey::RSA.new 2048
    # Verschlüsseln des Private keys
    $privkey_user = keys.to_pem
    cipher = OpenSSL::Cipher::AES.new(128, :ECB)
    cipher.encrypt
    cipher.key = masterkey
    privkey_user_enc = cipher.update($privkey_user) + cipher.final
    # privkey_user von PEM Format wieder in ein RSA Keypair umwandeln
    $privkey_user = keys

    #Übermittlung des user, salt_masterkey, pubkey & priv_key_user_enc an den Dienstanbieter
    response = HTTParty.post("http://#{WebClient::Application::SERVER_IP}/",
                  :body => {:identity => @user.name,
                            :salt_masterkey => salt_masterkey,
                            :pubkey_user => Base64.encode64(keys.public_key.to_pem),
                            :privkey_user_enc => Base64.encode64(privkey_user_enc)
                  }.to_json,
                  :headers => { 'Content-Type' => 'application/json'} )
    puts "============================================"
    puts "Größe Pubkey: #{Base64.encode64(keys.public_key.to_pem).size}"
    puts "Größe Privkey: #{Base64.encode64(privkey_user_enc).size}"
    puts "Status Code: #{response["status_code"]}"
    puts response.to_s
    puts "============================================"
    respond_to do |format|
      if response["status_code"].to_s == "110"
        puts "============================================"
        puts "User created"
        puts "============================================"
        if @user.save
          log_in @user
          format.html { redirect_to messages_url, notice: 'User was successfully created.' }
          format.json { render :show, status: :created, location: @user }
        else
          # User konnte lokal nicht persistiert werden
          format.html { render :new }
          format.json { render json: @user.errors, status: :unprocessable_entity }
        end
      else
        # User konnte beim Dienstanbieter nicht persistiert werden
        format.html { render :new }
        format.json { render json: @user.errors, status: :unprocessable_entity }
      end
    end
  end

  # PATCH/PUT /users/1
  # PATCH/PUT /users/1.json
  def update
    respond_to do |format|
      if @user.update(user_params)
        format.html { redirect_to @user, notice: 'User was successfully updated.' }
        format.json { render :show, status: :ok, location: @user }
      else
        format.html { render :edit }
        format.json { render json: @user.errors, status: :unprocessable_entity }
      end
    end
  end

  # DELETE /users/1
  # DELETE /users/1.json
  def destroy
    respond_to do |format|
      response = HTTParty.delete("http://#{WebClient::Application::SERVER_IP}/#{@user.name}")

      if response["status"] == "200"
        @user.destroy
        format.html { redirect_to( root_url, notice: 'User was successfully destroyed.') }
        format.json { head :no_content }
      else
        format.html { redirect_to users_url, notice: 'User konnte nicht gelöscht werden.'}
      end
    end
  end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_user
      @user = User.find(params[:id])
    end

    # Never trust parameters from the scary internet, only allow the white list through.
    def user_params
      params.require(:user).permit(:name, :password)
    end
end
