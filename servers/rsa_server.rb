require 'webrick'
require 'net/http'
require 'json'
require 'openssl'
require_relative '../crypt_util'
require_relative '../utils'
require_relative './http_server'

module Servers
  class RSAServer < HTTPServer
    
    E = 3
    
    def self.encrypt(plaintext, e, n)
      Utils::MathUtil.modexp(Utils::HexString.from_bytes(plaintext.bytes).hex, e, n)
    end

    def self.decrypt(ciphertext, d, n)
      Utils::MathUtil.modexp(ciphertext, d, n).to_s(16).extend(Utils::HexString).to_ascii
    end
    
    def initialize(port, message = '')
      super
      reset_keys
      mount
    end
    
    def reset_keys(bit_size = 1024)
      @p = OpenSSL::BN.generate_prime(bit_size).to_i
      @q = OpenSSL::BN.generate_prime(bit_size).to_i
      @n = @p * @q
      @private_key = Utils::MathUtil.invmod(E, (@p - 1) * (@q - 1))
    end

    def mount
      super
      @server.mount_proc('/publicKey') do |req, res|
        res.body = { e: E, n: @n }.to_json
      end

      @server.mount_proc('/receiveMessage') { |req| @message = self.class.decrypt(req.body.hex, @private_key, @n) }

      @server.mount_proc('/sendMessage') do |req|
        dest_port = JSON.parse(req.body)['port']
        public_key = JSON.parse(get_from('/publicKey', dest_port).body)
        post_text('/receiveMessage', JSON.parse(req.body)['port'], self.class.encrypt(@message, public_key['e'], public_key['n']).to_s(16))
      end
    end

    def send_message_to(serv)
      post_json('/sendMessage', @port, { port: serv.port })
    end
  end
end
