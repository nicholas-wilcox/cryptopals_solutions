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
    start_servers = lambda do
      s_a = Servers::DiffieHellmanServer.new(8080, plaintext)
      s_b = Servers::DiffieHellmanServer.new(8081)
      Thread.new { s_a.routine }
      Thread.new { s_b.routine }
      [s_a, s_b]
    end
    shutdown_all = lambda { |*servers| servers.each(&:shutdown) }

    it 'performs Diffie-Hellman protocol' do
      s_a, s_b = start_servers.call
      s_a.start_session(s_b)
      s_a.send_message_to(s_b)
      expect(s_b.message).to eq(plaintext);
      shutdown_all.call(s_a, s_b)
    end

    it 'Challenge 34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection' do
      s_a, s_b = start_servers.call
      mitm = Set5.challenge34(8082, s_b.port)
      Thread.new { mitm.routine }

      s_a.start_session(mitm)
      s_a.send_message_to(mitm)
      expect(s_b.message).to eq(plaintext)
      expect(mitm.message).to eq(plaintext)
      shutdown_all.call(s_a, s_b, mitm)
    end

    it 'Challenge 35: Implement DH with negotiated groups, and break with malicious "g" parameters' do
      fake_g_mitm = lambda do |i|
        s_a, s_b = start_servers.call
        mitm = Set5.challenge35(8082, s_b.port, i)
        Thread.new { mitm.routine }

        s_a.start_session(mitm)
        s_a.send_message_to(mitm)
        b_message = s_b.message
        mitm_message = mitm.message
        shutdown_all.call(s_a, s_b, mitm)
        [mitm_message, b_message]
      end

      (-1..1).each do |i|
        mitm_message, b_message = fake_g_mitm.call(i)
        expect(b_message).to eq(plaintext)
        expect(mitm_message).to eq(plaintext)
      end
    end
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
    
    it 'Perform Simple SRP login' do
      simple_srp_server = Servers::SimpleSRPServer.new(2001)
      simple_srp_server.add_login(username, password)
      Thread.new { simple_srp_server.routine }
      expect(Servers::SimpleSRPServer.login(simple_srp_server.port, username, password)).to eq(Servers::SRPServer::OK)
    end
    
    it 'Challenge 38: Offline dictionary attack on simplified SRP' do
      random_password = IO.readlines('/usr/share/dict/words', chomp: true).sample
      mitm_thread = Thread.new { Set5.challenge38(2002) }
      sleep(1) # Allow time for MITM server to activate
      Servers::SimpleSRPServer.login(2002, username, random_password)
      expect(mitm_thread.value).to eq(random_password)
    end
  end

  it 'Challenge 39: Implement RSA' do
    plaintext = Random.bytes(rand(50..100))
    s_a = Servers::RSAServer.new(8080, plaintext)
    s_b = Servers::RSAServer.new(8081)
    Thread.new { s_a.routine }
    Thread.new { s_b.routine }

    s_a.send_message_to(s_b)
    expect(s_b.message).to eq(plaintext);

    s_a.shutdown
    s_b.shutdown
  end

  it 'Challenge 40: Implement an E=3 RSA Broadcast attack' do
    plaintext = Random.bytes(rand(50...100))
    generate_ciphertext_and_public_key = lambda do
      p = OpenSSL::BN.generate_prime(bit_size).to_i
      q = OpenSSL::BN.generate_prime(bit_size).to_i
      n = p * q

    end

  end
end
