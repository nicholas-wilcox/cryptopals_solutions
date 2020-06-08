# frozen_string_literal: true

require 'socket'
require_relative '../utils'
require_relative 'srp_server'

module Servers
  class SimpleSRPServer < SRPServer

    def self.login(port, username, password)
      a = rand(0...N)
      s = TCPSocket.new('localhost', port)
      s.puts username
      a_pub = modexp_n(G, a)
      s.puts a_pub.to_s(16)

      salt = s.gets.chomp.extend(Utils::HexString).to_ascii
      b_pub = s.gets.chomp.hex
      u = s.gets.chomp.hex
      
      x = hash(salt, password).hex
      key = hash(modexp_n(b_pub, (a + (u * x)) % N))
      s.puts hmac(key, salt)
      s.gets.chomp
    end
    
    def routine
      loop do
        Thread.start(@server.accept) do |client|
          trap('INT') do
            client.close
            break
          end
          b = rand(0...N)
          salt = Random.bytes(8)
          u = Utils::HexString.from_bytes(Random.bytes(16).bytes).hex

          username = client.gets.chomp
          v = self.class.modexp_n(G, self.class.hash(salt, @password_table[username]).hex)
          b_pub = self.class.modexp_n(G, b)

          a_pub = client.gets.chomp.hex
          client.puts Utils::HexString.from_bytes(salt.bytes)
          client.puts b_pub.to_s(16)
          client.puts u.to_s(16)
          
          key = self.class.hash(self.class.modexp_n(a_pub * self.class.modexp_n(v, u), b))
          client.puts client.gets.chomp == self.class.hmac(key, salt) ? OK : NO
          client.close
        end
      end
    end
  end
end
