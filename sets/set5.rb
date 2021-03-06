require 'json'
require 'net/http'
require 'socket'
require_relative '../servers'
require_relative '../crypt_util'
require_relative '../utils'

module Set5
  module_function

  def challenge34(port_m, port_b)
    mitm = Servers::DiffieHellmanServer.new(port_m)
    
    mitm.server.mount_proc('/negotiate') do |req, res|
      request = JSON.parse(req.body)
      ack = mitm.post_json('/negotiate', port_b, { p: request['p'], g: request['g'] })
      if (ack.is_a?(Net::HTTPOK))
        mitm.post_text('/exchange', port_b, '0')
      end
      res.status = 200
    end

    mitm.server.mount_proc('/exchange') { |req, res| res.body = '0' }

    mitm.server.mount_proc('/receiveMessage') do |req|
      mitm.post_text('/receiveMessage', port_b, req.body)
      mitm.key_hash = CryptUtil::Digest::SHA1.digest(Utils::IntegerUtil.bytes(0).map(&:chr).join)[0, 16]
      mitm.message = mitm.decrypt(req.body.extend(Utils::HexString).to_ascii)
    end

    mitm
  end

  def challenge35(port_m, port_b, i)
    mitm = Servers::DiffieHellmanServer.new(port_m)
    pub_key = nil
    mitm.server.mount_proc('/negotiate') do |req, res|
      prime = JSON.parse(req.body)['p']
      fake_g = i % prime
      pub_key = Utils::MathUtil.modexp(fake_g, 2, prime)
      ack = mitm.post_json('/negotiate', port_b, { p: prime, g: fake_g})
      if (ack.is_a?(Net::HTTPOK))
        res.status = 200
      else
        res.status = 500
      end
    end

    mitm.server.mount_proc('/exchange') do |req, res|
      res.body = mitm.post_text('/exchange', port_b, pub_key.to_s(16)).body
    end

    mitm.server.mount_proc('/receiveMessage') do |req|
      mitm.post_text('/receiveMessage', port_b, req.body)
      mitm.key_hash = CryptUtil::Digest::SHA1.digest(Utils::IntegerUtil.bytes(pub_key).map(&:chr).join)[0, 16]
      mitm.message = mitm.decrypt(req.body.extend(Utils::HexString).to_ascii)
    end

    mitm
  end

  def challenge37(srv_port, username)
    s = TCPSocket.new('localhost', srv_port)
    s.puts username
    s.puts 0.to_s(16)

    salt = s.gets.chomp.extend(Utils::HexString).to_ascii
    s.gets.chomp.hex # b_pub
    key = Servers::SRPServer.hash(0)
    s.puts Servers::SRPServer.hmac(key, salt)

    s.gets.chomp
  end

  def challenge38(srv_port)
    server = TCPServer.new(srv_port)
    client = server.accept
    trap('INT') do
      client.close
      break
    end
    salt = ''
    client.gets.chomp # username
    a_pub = client.gets.chomp.hex
    client.puts Utils::HexString.from_bytes(salt.bytes)
    client.puts Servers::SRPServer::G.to_s(16) # b_pub, where b = 1
    client.puts 1.to_s(16) # u
    key_hmac = client.gets.chomp
    client.puts Servers::SRPServer::OK
    client.close

    IO.readlines('/usr/share/dict/words', chomp: true).find(-> { '' }) do |password|
      v = Servers::SRPServer.modexp_n(Servers::SRPServer::G, Servers::SRPServer.hash(password).hex)
      key = Servers::SRPServer.hash((a_pub * v) % Servers::SRPServer::N)
      key_hmac == Servers::SRPServer.hmac(key, salt)
    end
  end

  def challenge40(c1, c2, c3)
    x = Utils::MathUtil.crt(*[c1, c2, c3].map { |c| [c[:ciphertext], c[:public_key][:n]] }.transpose)
    Math.cbrt(x).to_i.to_s(16).extend(Utils::HexString).to_ascii
  end
end
