module MessagesHelper
  def fetchMessages
    timestamp = Time.now.to_i
    digest = OpenSSL::Digest::SHA256.new
    document = current_user.name.to_s+timestamp.to_s
    sig_user = $privkey_user.sign digest, document
    puts '==============================='
    puts document
    puts '==============================='
    puts Base64.encode64(sig_user)
    puts '==============================='
    response = HTTParty.post("http://#{WebClient::Application::SERVER_IP}/#{current_user.name}/messages",
                            :body => {:sig_message => Base64.encode64(sig_user),
                                      :timestamp => timestamp
                            }.to_json,
                            :headers => { 'Content-Type' => 'application/json'} )

    puts "============================================"
    puts response
    puts response.length
    puts "============================================"

      if !(response.include? "status_code")
        response.each do |item|
        #nachricht abholen
        timestamp = Time.now.to_i
        document = current_user.name.to_s+timestamp.to_s
        sig_user = $privkey_user.sign digest, document
        response_message = HTTParty.post("http://#{WebClient::Application::SERVER_IP}/#{current_user.name}/message",
                                        :body => {:sig_message => Base64.encode64(sig_user),
                                                  :timestamp => timestamp,
                                                  :message_id => item["message_id"].to_i
                                        }.to_json,
                                        :headers => { 'Content-Type' => 'application/json'} )
        puts "============================================"
        puts response_message.to_s
        puts "============================================"

        if item["read"].equal?(false)
          puts "============================================"
          puts "unread message"
          puts "============================================"

          # Signaturprüfung
            response_pubkey = HTTParty.get("http://#{WebClient::Application::SERVER_IP}/#{item["identity"]}/pubkey")
            pubkey_sender = OpenSSL::PKey::RSA.new(Base64.decode64(response_pubkey["pubkey_user"]))

            document = response_message["identity"].to_s+Base64.decode64(response_message["cipher"]).to_s+Base64.decode64(response_message["iv"]).to_s+Base64.decode64(response_message["key_recipient_enc"]).to_s

           if pubkey_sender.verify digest, Base64.decode64(response_message["sig_recipient"]), document
              puts "============================================"
              puts "sig_recipient valid"
              puts "============================================"
              # entschlüsselung der cipher
              decipher = OpenSSL::Cipher.new('AES-128-CBC')
              decipher.padding =1
              decipher.decrypt
              decipher.key = $privkey_user.private_decrypt(Base64.decode64(response_message["key_recipient_enc"].to_s))
              decipher.iv = Base64.decode64(response_message["iv"])

              message = decipher.update(Base64.decode64(response_message["cipher"])) + decipher.final

              @message = Message.new(sender: item["identity"], message: message, recipient: current_user.name)
              @message.save
              puts "============================================"
              puts "cipher decrypted and saved"
              puts "============================================"
           end
        end
          end
      end
  end
end
