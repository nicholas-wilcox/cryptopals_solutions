# frozen_string_literal: true

require_relative '../../sets/set6'
require_relative '../../utils'
require_relative '../../servers'

RSpec.describe 'Set6' do
  it 'Challenge 41: Implement unpadded message recovery oracle' do
    plaintext = Random.bytes(20)
    p = OpenSSL::BN.generate_prime(1024).to_i
    q = OpenSSL::BN.generate_prime(1024).to_i
    n = p * q
    d = Utils::MathUtil.invmod(Servers::RSAServer::E, (p - 1) * (q - 1))

    ciphertext = Servers::RSAServer.encrypt(plaintext, Servers::RSAServer::E, n)
    decrypt = lambda { |s| Servers::RSAServer.decrypt(s, d, n) }

    expect(Set6.challenge41(ciphertext, Servers::RSAServer::E, n, decrypt)).to eq(plaintext)
  end
end
