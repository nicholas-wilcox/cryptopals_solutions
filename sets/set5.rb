require 'net/http'
require_relative '../servers'
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
      p res.body
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
    b_pub = s.gets.chomp.hex
    key = Servers::SRPServer.hash(0)
    s.puts Servers::SRPServer.hmac(key, salt)

    s.gets.chomp
  end
end
