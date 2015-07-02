class MessagesController < ApplicationController
  before_action :set_message, only: [:show, :edit, :update, :destroy]
  before_action :authenticate

  # GET /messages
  # GET /messages.json
  def index
    fetchMessages
    #@messages = Message.all
    @messages = Message.where(recipient: current_user.name)

  end

  # GET /messages/1
  # GET /messages/1.json
  def show
  end

  # GET /messages/new
  def new
    fetchRecipients
    @message = Message.new
  end

  # GET /messages/1/edit
  def edit
  end

  # POST /messages
  # POST /messages.json
  def create
    @message = Message.new(message_params)
    post_message

    respond_to do |format|

        format.html { redirect_to @message, notice: 'Message was successfully created.' }
        format.json { render :show, status: :created, location: @message }
    end
  end

  # PATCH/PUT /messages/1
  # PATCH/PUT /messages/1.json
  def update
    respond_to do |format|
      if @message.update(message_params)
        format.html { redirect_to @message, notice: 'Message was successfully updated.' }
        format.json { render :show, status: :ok, location: @message }
      else
        format.html { render :edit }
        format.json { render json: @message.errors, status: :unprocessable_entity }
      end
    end
  end

  # DELETE /messages/1
  # DELETE /messages/1.json
  def destroy
    @message.destroy
    puts "============================================"
    puts "Message deleted"
    puts "============================================"
    respond_to do |format|
      format.html { redirect_to messages_url, notice: 'Message was successfully destroyed.' }
      format.json { head :no_content }
    end
  end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_message
      @message = Message.find(params[:id])
    end

    # Never trust parameters from the scary internet, only allow the white list through.
    def message_params
      params.require(:message).permit(:sender, :message, :recipient)
    end

    def post_message
      @user = current_user

      # Pubkey des Users holen
      response = HTTParty.get("http://#{WebClient::Application::SERVER_IP}/#{@message.recipient}/pubkey")
      pubkey_recipient = OpenSSL::PKey::RSA.new(Base64.decode64(response["pubkey_user"]))
      puts "============================================"
      puts "Pubkey User: " + pubkey_recipient.to_s
      puts "============================================"


      # Nachricht verschlüsseln
      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.padding = 1
      cipher.encrypt
      cipher.key_len = 16
      key_recipient = cipher.random_key
      iv = cipher.random_iv
      cipher.iv = iv
      encrypted_message = cipher.update(@message.message) + cipher.final

      # Verschlüsselung des key_recipient zu key_recipient_enc mittels RSA
      key_recipient_enc = pubkey_recipient.public_encrypt(key_recipient.to_s)

      # inner_envelope für die Signaturbestimmung bilden
      inner_envelope = @user.name.to_s+encrypted_message.to_s+iv.to_s+key_recipient_enc.to_s

      # Signatur sig_recipient bilden
      digest = OpenSSL::Digest::SHA256.new
      sig_recipient = $privkey_user.sign digest, inner_envelope

      # Signatur sig_service bilden
      timestamp = Time.now.to_i
      document = @message.recipient.to_s + inner_envelope.to_s+ timestamp.to_s
      puts document

      sig_service = $privkey_user.sign digest, document

      #sig_service = OpenSSL::HMAC.hexdigest('sha256', $privkey_user, document)

      response = HTTParty.post("http://#{WebClient::Application::SERVER_IP}/message",
                               :body => {:inner_envelope  => {:sender              => @user.name,
                                                              :cipher                => Base64.encode64(encrypted_message),
                                                              :iv                    => Base64.encode64(iv),
                                                              :key_recipient_enc     => Base64.encode64(key_recipient_enc),
                                                              :sig_recipient         => Base64.encode64(sig_recipient)},
                                        :timestamp => timestamp,
                                        :recipient => @message.recipient,
                                        :sig_service => Base64.encode64(sig_service)
                               }.to_json,
                               :headers => { 'Content-Type' => 'application/json'} )
      puts "============================================"
      puts "Status Code: #{response["status_code"]}"
      puts "============================================"
      if response["status_code"].to_s == '122'
        puts "============================================"
        puts "Message created"
        puts "============================================"
      end
    end
end
