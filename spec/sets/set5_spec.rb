# frozen_string_literal: true

require_relative '../../sets/set5'
require_relative '../../utils'
require_relative '../../servers'

RSpec.describe 'Set5' do
  context 'Challenge 33: Implement Diffie-Hellman' do
    cons_modexp = lambda { |g, *e, p| e.reduce(g) { |x, e| Utils::MathUtil.modexp(x, e, p) } }
    dh_exchange = lambda do |g, p|
      a = rand(0...p)
      b = rand(0...p)
      return cons_modexp.call(g, a, b, p), cons_modexp.call(g, b, a, p)
    end

    it 'small numbers' do
      k_a, k_b = dh_exchange.call(5, 37)
      expect(k_a).to eq(k_b)
    end

    it 'big numbers' do
      k_a, k_b = dh_exchange.call(Servers::DiffieHellmanServer::G, Servers::DiffieHellmanServer::P)
      expect(k_a).to eq(k_b)
    end
  end

  context 'Diffie Hellman' do
    plaintext = Random.bytes(rand(50..100))
    s_a = Servers::DiffieHellmanServer.new(8080, plaintext)
    s_b = Servers::DiffieHellmanServer.new(8081)
    Thread.new { s_a.routine }
    Thread.new { s_b.routine }

    after(:example) { s_b.message = '' }

    it 'performs Diffie-Hellman protocol' do
      s_a.start_session(s_b)
      s_a.send_message_to(s_b)
      expect(s_b.message).to eq(plaintext);
    end

    it 'Challenge 34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection' do
      mitm = Set5.challenge34(8082, s_b.port)
      Thread.new { mitm.routine }

      s_a.start_session(mitm)
      s_a.send_message_to(mitm)
      expect(s_b.message).to eq(plaintext)
      expect(mitm.message).to eq(plaintext)
      mitm.shutdown
    end

    it 'Challenge 35: Implement DH with negotiated groups, and break with malicious "g" parameters' do
      (-1..1).each do |i|
        mitm = Set5.challenge35(8082, s_b.port, i)
        Thread.new { mitm.routine }

        s_a.start_session(mitm)
        s_a.send_message_to(mitm)
        expect(s_b.message).to eq(plaintext)
        expect(mitm.message).to eq(plaintext)
        mitm.shutdown
        s_b.message = ''
      end
    end

    s_a.shutdown
    s_b.shutdown
  end

  username = 'firstname.lastname@gmail.com'
  password = 'password123'
  
  context 'Secure Remote Protocal' do
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

  context 'Challenge 38: Offline dictionary attack on simplified SRP' do
    srp_server = Servers::SimpleSRPServer.new(2001)
    srp_server.add_login(username, password)
    Thread.new { srp_server.routine }
    
    it 'Perform Simple SRP login' do
      expect(Servers::SimpleSRPServer.login(srp_server.port, username, password)).to eq(Servers::SRPServer::OK)
    end
    
    it 'MITM attack' do
    end
  end

end
