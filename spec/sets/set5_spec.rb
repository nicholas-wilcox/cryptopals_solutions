# frozen_string_literal: true

require_relative '../../sets/set5'
require_relative '../../utils'
require 'webrick'
require 'net/http'
require 'json'
require 'socket'
require 'openssl'
require_relative '../../crypt_util'
require_relative '../../servers'

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

  context 'Diffie Hellman' do
    it 'performs Diffie-Hellman protocol' do
      s_a = Servers::DiffieHellmanServer.new(8080)
      s_a.message = plaintext
      s_b = Servers::DiffieHellmanServer.new(8081)

      Thread.new { s_a.routine }
      Thread.new { s_b.routine }

      s_a.start_session(s_b)
      s_a.send_message_to(s_b)
      expect(s_b.message).to eq(plaintext);
      s_a.shutdown
      s_b.shutdown
    end

    it 'Challenge 34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection' do
      s_a = Servers::DiffieHellmanServer.new(8080)
      s_a.message = plaintext
      s_b = Servers::DiffieHellmanServer.new(8081)

      mitm = Set5.challenge34(8082, s_b.port)

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

  it 'Challenge 35: Implement DH with negotiated groups, and break with malicious "g" parameters' do
    s_a = Servers::DiffieHellmanServer.new(8080)
    s_a.message = plaintext
    s_b = Servers::DiffieHellmanServer.new(8081)
    
    Thread.new { s_a.routine }
    Thread.new { s_b.routine }
    
    (-1..1).each do |i|
      mitm = Set5.challenge35(8082, s_b.port, i)
      Thread.new { mitm.routine }

      s_a.start_session(mitm)
      s_a.send_message_to(mitm)
      expect(s_b.message).to eq(plaintext)
      expect(mitm.message).to eq(plaintext)
      mitm.shutdown
    end

    s_a.shutdown
    s_b.shutdown
  end

  context 'Secure Remote Protocal' do
    username = 'firstname.lastname@gmail.com'
    password = 'password123'

    srp_server = Servers::SRPServer.new(2000)
    srp_server.add_login(username, password)
    Thread.new { srp_server.routine }
    
    it 'Challenge 36: Implement Secure Remote Password (SRP)' do
      expect(Servers::SRPServer.login(srp_server.port, username, password)).to eq(Servers::SRPServer::OK)
    end
    
    it 'Challenge 37: Break SRP with a zero key' do
      expect(Set5.challenge37(srp_server.port, username)).to eq(Servers::SRPServer::OK)
    end
  end

end
