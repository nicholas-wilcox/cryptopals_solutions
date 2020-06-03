# frozen_string_literal: true

require_relative '../../sets/set5'
require_relative '../../utils'
require 'webrick'
require 'net/http'
require 'json'
require_relative '../../crypt_util'

RSpec.describe 'Set5' do

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
      server_a = DiffieHellmanServer.new(8080, 'A')
      server_b = DiffieHellmanServer.new(8081, 'B')

      Thread.new { server_a.routine }
      Thread.new { server_b.routine }
      original = 'Hello, World!'
      server_a.setMessage(original)

      DiffieHellmanServer.exchange(server_a, server_b)
      server_a.sendMessageTo(server_b)
      expect(server_b.getMessage).to eq(original);
      server_a.shutdown
      server_b.shutdown
    end

    it 'performs MITM attack' do
      server_a = DiffieHellmanServer.new(8080, 'A')
      server_b = DiffieHellmanServer.new(8081, 'B')
      mitm = DiffieHellmanServer.new(8082, 'M')
      
      Thread.new { server_a.routine }
      Thread.new { server_b.routine }
      Thread.new { mitm.routine }
      
      original = 'Hello, World!'
      server_a.setMessage(original)
      mitm.setPubKey(0)

      DiffieHellmanServer.mitm(server_a, server_b, mitm)
      expect(server_a.getMessage).to eq(original)
      expect(server_b.getMessage).to eq(original)
      expect(mitm.getMessage).to eq(original)

      server_a.shutdown
      server_b.shutdown
      mitm.shutdown
    end
  end


end
