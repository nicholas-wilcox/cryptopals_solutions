# frozen_string_literal: true

require_relative '../../sets/set5'
require_relative '../../utils'
require 'webrick'
require 'net/http'
require 'json'
require_relative '../../crypt_util'

RSpec.describe 'Set5' do

  plaintext = Random.bytes(rand(50..100))

  context 'Challenge 33: Implement Diffie-Hellman' do
    it 'small numbers' do
      p = 37
      g = 5
      a = rand(0...p)
      b = rand(0...p)
      a_pub = Utils::MathUtil.modexp(g, a, p)
      b_pub = Utils::MathUtil.modexp(g, b, p)

      expect(Utils::MathUtil.modexp(b_pub, a, p)).to eq(Utils::MathUtil.modexp(a_pub, b, p))
    end

    it 'big numbers' do
      p = ('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024' +
           'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd' +
           '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec' +
           '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f' +
           '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361' +
           'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552' +
           'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff' +
           'fffffffffffff').hex
      g = 2
      a = rand(0...p)
      b = rand(0...p)
      a_pub = Utils::MathUtil.modexp(g, a, p)
      b_pub = Utils::MathUtil.modexp(g, b, p)

      expect(Utils::MathUtil.modexp(b_pub, a, p)).to eq(Utils::MathUtil.modexp(a_pub, b, p))
    end
  end

  context 'Challenge 34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection' do
    it 'performs Diffie-Hellman protocol' do
      s_a = DiffieHellmanServer.new(8080)
      s_a.message = plaintext
      s_b = DiffieHellmanServer.new(8081)

      Thread.new { s_a.routine }
      Thread.new { s_b.routine }

      s_a.start_session(s_b)
      s_a.send_message_to(s_b)
      expect(s_b.message).to eq(plaintext);
      s_a.shutdown
      s_b.shutdown
    end

    it 'performs MITM attack' do
      s_a = DiffieHellmanServer.new(8080)
      s_a.message = plaintext
      s_b = DiffieHellmanServer.new(8081)
      mitm = DiffieHellmanServer.new(8082)
      
      mitm.server.mount_proc('/negotiate') do |req, res|
        request = JSON.parse(req.body)
        ack = mitm.post_json('/negotiate', s_b.port, { p: request['p'], g: request['g'] })
        if (ack.is_a?(Net::HTTPOK))
          mitm.post_text('/exchange', s_b.port, '0')
        end
        res.status = 200
      end

      mitm.server.mount_proc('/exchange') { |req, res| res.body = '0' }

      mitm.server.mount_proc('/receiveMessage') do |req|
        mitm.post_text('/receiveMessage', s_b.port, req.body)
        mitm.key_hash = CryptUtil::Digest::SHA1.digest(Utils::IntegerUtil.bytes(0).map(&:chr).join)[0, 16]
        mitm.message = mitm.decrypt(req.body.extend(Utils::HexString).to_ascii)
      end

      Thread.new { s_a.routine }
      Thread.new { s_b.routine }
      Thread.new { mitm.routine }

      s_a.start_session(mitm)
      s_a.send_message_to(mitm)
      expect(s_b.message).to eq(plaintext)
      expect(mitm.message).to eq(plaintext)

      s_a.shutdown
      s_b.shutdown
      mitm.shutdown
    end
  end

  it 'Challenge 35: Implement DH with negotiated groups, and break with malicious "g" parameters', :focus => true do
    s_a = DiffieHellmanServer.new(8080)
    s_a.message = plaintext
    s_b = DiffieHellmanServer.new(8081)
    mitm = DiffieHellmanServer.new(8082)
    
    fake_g = 1

    mitm.server.mount_proc('/negotiate') do |req, res|
      request = JSON.parse(req.body)
      ack = mitm.post_json('/negotiate', s_b.port, { p: request['p'], g: fake_g })
      if (ack.is_a?(Net::HTTPOK))
        res.status = 200
      else
        res.status = 500
      end
    end

    mitm.server.mount_proc('/exchange') do |req, res|
      res.body = mitm.post_text('/exchange', s_b.port, fake_g.to_s(16)).body
    end

    mitm.server.mount_proc('/receiveMessage') do |req|
      mitm.post_text('/receiveMessage', s_b.port, req.body)
      mitm.key_hash = CryptUtil::Digest::SHA1.digest(Utils::IntegerUtil.bytes(fake_g).map(&:chr).join)[0, 16]
      mitm.message = mitm.decrypt(req.body.extend(Utils::HexString).to_ascii)
    end

    Thread.new { s_a.routine }
    Thread.new { s_b.routine }
    Thread.new { mitm.routine }

    s_a.start_session(mitm)
    s_a.send_message_to(mitm)
    expect(s_b.message).to eq(plaintext)
    expect(mitm.message).to eq(plaintext)

    s_a.shutdown
    s_b.shutdown
    mitm.shutdown
  end


end
