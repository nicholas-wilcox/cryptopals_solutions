# frozen_string_literal: true

require_relative '../utils'
require_relative '../set2'
require_relative '../crypt_util'
require 'openssl'

RSpec.describe 'Set2' do
  it 'Challenge 9: Implement PKCS#7 padding' do
    expect(CryptUtil.pad('YELLOW SUBMARINE', 20)).to eq("YELLOW SUBMARINE\x04\x04\x04\x04")
  end

  context 'Challenge 10: Implement CBC mode' do
    r = seeded_rng
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

  context 'Challenge 11: And ECB/CBC detection oracle' do
    r = seeded_rng
    key = r.bytes(16)
    iv = r.bytes(16)
    prefix = r.bytes(r.rand(5..10))
    suffix = r.bytes(r.rand(5..10))
    oracle_for = proc do |cipher|
      proc do |input|
        case cipher
        when :ECB
          CryptUtil.aes_128_ecb(prefix + input + suffix, key, :encrypt)
        when :CBC
          CryptUtil.aes_128_cbc(prefix + input + suffix, key, :encrypt, iv)
        end
      end
    end

    it 'Detects ECB' do
      expect(Set2.challenge11(oracle_for.call(:ECB))).to eq(:ECB)
    end

    it 'Detects CBC' do
      expect(Set2.challenge11(oracle_for.call(:CBC))).to eq(:CBC)
    end
  end

  it 'Challenge 12: Byte-at-a-time ECB decryption (Simple)' do
    text = path_to('data/challenge12.txt').open { |file| Utils::Base64.decode(file.read) }
    key = seeded_rng.bytes(16)
    encryption_oracle = proc { |input| CryptUtil.aes_128_ecb(input + text, key, :encrypt) }
    expect(Set2.challenge12(encryption_oracle)).to eq(text)
  end

  it 'Challenge 13: ECB cut-and-paste' do
    key = seeded_rng.bytes(16)
    profile_for = proc { |email| { email: email.tr('&=', ''), uid: 1234, role: 'user' }.extend(Utils::HashUtil).to_query }
    oracle = proc { |email| CryptUtil.aes_128_ecb(profile_for.call(email), key, :encrypt) }
    decrypt_profile = proc { |s| Utils::HashUtil.from_query(CryptUtil.aes_128_ecb(s, key, :decrypt)) }

    expect(decrypt_profile.call(Set2.challenge13(oracle))[:role]).to eq('admin')
  end
  
  it 'Challenge 14: Byte-at-a-time ECB decryption (Harder)' do
    text = path_to('data/challenge12.txt').open { |file| Utils::Base64.decode(file.read) }
    r = seeded_rng
    key = r.bytes(16)
    prefix = r.bytes(r.rand(50..100))
    encryption_oracle = proc { |input| CryptUtil.aes_128_ecb(prefix + input + text, key, :encrypt) }
    expect(Set2.challenge14(encryption_oracle)).to eq(text)
  end

  context 'Challenge 15: PKCS#7 padding validation' do
    it 'removes valid padding' do
      expect(CryptUtil.remove_pad("ICE ICE BABY\x04\x04\x04\x04")).to eq('ICE ICE BABY')
    end

    it 'raises ArgumentError when removing invalid padding' do
      expect { CryptUtil.remove_pad("ICE ICE BABY\x05\x05\x05\x05") }.to raise_error(ArgumentError, CryptUtil::INVALID_PAD_ERROR)
      expect { CryptUtil.remove_pad("ICE ICE BABY\x01\x02\x03\x04") }.to raise_error(ArgumentError, CryptUtil::INVALID_PAD_ERROR)
    end
  end

  it 'Challenge 16: CBC bitflipping attacks' do
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    key = seeded_rng.bytes(16)
    oracle = proc { |input| CryptUtil.aes_128_cbc(prefix + input.gsub(/([;=])/, "'\\1'") + suffix, key, :encrypt) }
    is_admin = proc do |ciphertext|
      CryptUtil.aes_128_cbc(ciphertext, key, :decrypt).split(/(?<!');(?!')/)
        .map { |s| s.split(/(?<!')=(?!')/, 2) }
        .map { |k, v| [k.to_sym, v] }.to_h[:admin] == 'true'
    end

    expect(is_admin.call(Set2.challenge16(oracle))).to be true
  end

end
