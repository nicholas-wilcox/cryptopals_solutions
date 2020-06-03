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

  def initialize(port, name)
    @port = port
    @name = name
    @key = rand(0...P)
    @pub_key = Utils::MathUtil.modexp(G, @key, P)
    @session_key = nil
    @key_hash = nil
    @message = nil

    @server = WEBrick::HTTPServer.new({
      Port: @port
    })
  end

  def self.exchange(s1, s2)
    Net::HTTP.start('localhost', s1.port) do |http|
      http.post('/sendPubKey', { port: s2.port }.to_json, 'Content-Type' => 'application/json')
    end

    Net::HTTP.start('localhost', s2.port) do |http|
      http.post('/sendPubKey', { port: s1.port }.to_json, 'Content-Type' => 'application/json')
    end
  end

  def self.mitm(s1, s2, m)
    m.setPubKey(0)
    self.exchange(s1, m)
    self.exchange(s2, m)
    Net::HTTP.start('localhost', m.port) do |http|
      http.post('/mitm', { ciphertext: s1.encrypt(s1.getMessage).unpack1('H*'), port: s2.port }.to_json, { 'Content-Type': 'application/json' })
    end
  end

  def port
    @port
  end

  def routine
    trap('INT') { @server.shutdown }
    @server.mount_proc('/sendPubKey') do |req|
      Net::HTTP.start('localhost', JSON.parse(req.body)['port']) do |http|
        http.post('/receivePubKey', @pub_key.to_s(16), { 'Content-Type': 'text/plain' })
      end
    end

    @server.mount_proc('/receivePubKey') do |req|
      @session_key = Utils::MathUtil.modexp(req.body.hex, @key, P)
      @key_hash = CryptUtil::Digest::SHA1.digest(Utils::IntegerUtil.bytes(@session_key).map(&:chr).join)[0, 16]
    end

    @server.mount_proc('/getMessage') do |req, res|
      res.body = @message
    end

    @server.mount_proc('/setMessage') do |req|
      @message = req.body
    end

    @server.mount_proc('/setPubKey') do |req|
      @pub_key = req.body.hex
    end

    @server.mount_proc('/sendMessage') do |req|
      request = JSON.parse(req.body)
      Net::HTTP.start('localhost', JSON.parse(req.body)['port']) do |http|
        http.post('/receiveMessage', Utils::HexString.from_bytes(encrypt(@message).bytes), { 'Content-Type': 'text/plain' })
      end
    end

    @server.mount_proc('/receiveMessage') do |req|
      @message = decrypt(req.body.extend(Utils::HexString).to_ascii)
    end

    @server.mount_proc('/echoMessage') do |req, res|
      res.body = @message
    end

    @server.mount_proc('/mitm') do |req|
      request = JSON.parse(req.body)
      Net::HTTP.start('localhost', request['port']) do |http|
        http.post('/receiveMessage', request['ciphertext'], { 'Content-Type': 'text/plain' })
      end
      @key_hash = CryptUtil::Digest::SHA1.digest(Utils::IntegerUtil.bytes(0).map(&:chr).join)[0, 16]
      @message = decrypt(request['ciphertext'].extend(Utils::HexString).to_ascii)
    end

    @server.start
  end

  def encrypt(plaintext)
    iv = Random.bytes(16)
    CryptUtil.aes_128_cbc(plaintext, @key_hash, :encrypt, iv) + iv
  end

  def decrypt(ciphertext)
    CryptUtil.aes_128_cbc(ciphertext[0...-16], @key_hash, :decrypt, ciphertext[-16, 16])
  end

  def getMessage
    Net::HTTP.start('localhost', @port) do |http|
      http.get('/getMessage').body
    end
  end

  def setMessage(s)
    Net::HTTP.start('localhost', @port) do |http|
      http.post('/setMessage', s, { 'Content-Type': 'text/plain' })
    end
  end

  def setPubKey(k)
    Net::HTTP.start('localhost', @port) do |http|
      http.post('/setPubKey', k.to_s(16), { 'Content-Type': 'text/plain' })
    end
  end

  def sendMessageTo(serv)
    Net::HTTP.start('localhost', @port) do |http|
      http.post('/sendMessage', { port: serv.port }.to_json, { 'Content-Type': 'text/plain' })
    end
  end

  def shutdown
    @server.shutdown
  end
end
