require 'webrick'
require 'net/http'
require_relative '../crypt_util'
require_relative '../utils'

class DiffieHellmanServer
  
  P = ('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024' +
       'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd' +
       '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec' +
       '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f' +
       '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361' +
       'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552' +
       'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff' +
       'fffffffffffff').hex
  G = 2

  attr_reader :server
  attr_accessor :port, :key_hash 
  attr_writer :message, :pub_key

  def initialize(port)
    @port = port
    @session_key = nil

    reset_group
    reset_keys
    @server = WEBrick::HTTPServer.new({
      Port: @port
    })
    mount
  end

  def message
    get_from('/getMessage', @port).body
  end

  def reset_group(p = P, g = G)
    @p = p
    @g = g % @p
  end

  def reset_keys
    @key = rand(0...@p)
    @pub_key = Utils::MathUtil.modexp(@g, @key, @p)
  end

  def establish_session_key(other_pub)
    @session_key = Utils::MathUtil.modexp(other_pub, @key, @p)
    @key_hash = CryptUtil::Digest::SHA1.digest(Utils::IntegerUtil.bytes(@session_key).map(&:chr).join)[0, 16]
  end

  def mount
    @server.mount_proc('/startSession') do |req|
      request = JSON.parse(req.body)
      ack = post_json('/negotiate', request['port'], { p: @p, g: @g })
      if (ack.is_a?(Net::HTTPOK))
        res = post_text('/exchange', request['port'], @pub_key.to_s(16))
        establish_session_key(res.body.hex)
      end
    end

    @server.mount_proc('/negotiate') do |req, res|
      request = JSON.parse(req.body)
      reset_group(request['p'], request['g'])
      reset_keys
      res.status = 200
    end

    @server.mount_proc('/exchange') do |req, res|
      establish_session_key(req.body.hex)
      res.body = @pub_key.to_s(16)
    end

    @server.mount_proc('/receivePubKey') do |req|
      @session_key = Utils::MathUtil.modexp(req.body.hex, @key, P)
      @key_hash = CryptUtil::Digest::SHA1.digest(Utils::IntegerUtil.bytes(@session_key).map(&:chr).join)[0, 16]
    end

    @server.mount_proc('/sendPubKey') { |req| post_text('/receivePubKey', JSON.parse(req.body)['port'], @pub_key.to_s(16)) }
    @server.mount_proc('/getMessage') { |req, res| res.body = @message }
    @server.mount_proc('/receiveMessage') { |req| @message = decrypt(req.body.extend(Utils::HexString).to_ascii) }
    @server.mount_proc('/sendMessage') do |req|
      post_text('/receiveMessage', JSON.parse(req.body)['port'], Utils::HexString.from_bytes(encrypt(@message).bytes))
    end
  end

  def routine
    trap('INT') { @server.shutdown }
    @server.start
  end

  def post_text(endpoint, port, text)
    Net::HTTP.start('localhost', port) do |http|
      http.post(endpoint, text, { 'Content-Type': 'text/plain' })
    end
  end

  def post_json(endpoint, port, obj)
    Net::HTTP.start('localhost', port) do |http|
      http.post(endpoint, obj.to_json, { 'Content-Type': 'application/json' })
    end
  end

  def get_from(endpoint, port)
    Net::HTTP.start('localhost', port) do |http|
      http.get(endpoint)
    end
  end

  def encrypt(plaintext)
    iv = Random.bytes(16)
    CryptUtil.aes_128_cbc(plaintext, @key_hash, :encrypt, iv) + iv
  end

  def decrypt(ciphertext)
    CryptUtil.aes_128_cbc(ciphertext[0...-16], @key_hash, :decrypt, ciphertext[-16, 16])
  end

  def start_session(dest)
    post_json('/startSession', @port, { port: dest.port })
  end
  
  def send_message_to(serv)
    post_json('/sendMessage', @port, { port: serv.port })
  end

  def shutdown
    @server.shutdown
  end
end
