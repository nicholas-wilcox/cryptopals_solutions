# frozen_string_literal: true

require_relative '../utils'
require_relative '../set2'
require_relative 'helpers'
require_relative '../crypt_util'
require 'openssl'

RSpec.configure do |c|
  c.include Helpers
end

RSpec.describe 'Set2' do
  it 'Challenge 9: Implement PKCS#7 padding' do
    expect(CryptUtil.pad('YELLOW SUBMARINE', 20)).to eq("YELLOW SUBMARINE\x04\x04\x04\x04")
  end

  context 'Challenge 10: Implement CBC mode' do
    r = Random.new(RSpec.configuration.seed)
    key = r.bytes(16)
    iv = r.bytes(16)
    text = r.bytes(r.rand(50..100))

    it 'encrypts like OpenSSL::Cipher::AES' do
      cipher = OpenSSL::Cipher::AES.new(128, :CBC)
      cipher.send(:encrypt)
      cipher.key = key
      cipher.padding = 0
      cipher.iv = iv
      expect(CryptUtil.aes_128_cbc(text, key, :encrypt, iv)).to eq(cipher.update(CryptUtil.pad(text, 16)) + cipher.final)
    end

    it 'decrypts itself' do
      expect(CryptUtil.aes_128_cbc(CryptUtil.aes_128_cbc(text, key, :encrypt, iv), key, :decrypt, iv)).to eq(text)
    end
  end
end
