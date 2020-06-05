# frozen_string_literal: true

require 'socket'
require 'openssl'
require_relative '../utils'

module Servers
  class SRPServer

    OK = 'OK'
    NO = 'NO'
    N = ('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1' +
         '29024e088a67cc74020bbea63b139b22514a08798e3404dd' +
         'ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245' +
         'e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed' +
         'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d' +
         'c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f' +
         '83655d23dca3ad961c62f356208552bb9ed529077096966d' +
         '670c354e4abc9804f1746c08ca237327ffffffffffffffff').hex
    G = 2
    K = 3

    def self.hash(*args)
      OpenSSL::Digest::SHA256.hexdigest(args.map(&:to_s).join)
    end

    def self.modexp_n(x, e)
      Utils::MathUtil.modexp(x, e, N)
    end

    def self.hmac(key, m)
      OpenSSL::HMAC.hexdigest('sha256', key, m)
    end

    def self.login(port, username, password)
      a = rand(0...N)
      s = TCPSocket.new('localhost', port)
      s.puts username
      a_pub = modexp_n(G, a)
      s.puts a_pub.to_s(16)

      salt = s.gets.chomp.extend(Utils::HexString).to_ascii
      x = hash(salt, password).hex
      
      b_pub = s.gets.chomp.hex
      u = hash(a_pub.to_s, b_pub.to_s).hex
      key = hash(modexp_n(b_pub - (K * modexp_n(G, x)), (a + (u * x)) % N))
      s.puts hmac(key, salt)
      s.gets.chomp
    end
    
    attr_reader :port

    def initialize(port)
      @port = port
      @password_table = Hash.new
    end

    def add_login(username, password)
      @password_table[username] = password
    end

    def routine
      server = TCPServer.new(@port)
      loop do
        Thread.start(server.accept) do |client|
          trap('INT') do
            client.close
            break
          end
          b = rand(0...N)
          salt = Random.bytes(8)

          username = client.gets.chomp
          v = self.class.modexp_n(G, self.class.hash(salt, @password_table[username]).hex)
          b_pub = (self.class.modexp_n(G, b) + (K * v)) % N

          a_pub = client.gets.chomp.hex
          client.puts Utils::HexString.from_bytes(salt.bytes)
          client.puts b_pub.to_s(16)
          u = self.class.hash(a_pub.to_s, b_pub.to_s).hex
          key = self.class.hash(self.class.modexp_n(a_pub * self.class.modexp_n(v, u), b))
          client.puts client.gets.chomp == self.class.hmac(key, salt) ? OK : NO
          client.close
        end
      end
    end
  end
end
