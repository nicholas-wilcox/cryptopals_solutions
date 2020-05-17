# frozen_string_literal: true

require_relative '../utils'
require_relative '../set3'
require_relative '../cryptanalysis'

RSpec.describe 'Set3', :focus => true do

  it 'Challenge 17: The CBC padding oracle' do
    r = seeded_rng
    text = r.bytes(r.rand(50..100))
    key = r.bytes(16)
    iv = r.bytes(16)

    padding_oracle = proc do |ciphertext|
      CryptUtil.aes_128_cbc(ciphertext, key, :decrypt, iv)
      true
    rescue ArgumentError
      false
    end
    
    expect(Cryptanalysis.decrypt_cbc_padding_oracle(padding_oracle, iv, CryptUtil.aes_128_cbc(text, key, :encrypt, iv))).to eq(text)
  end

  it 'Challenge 18: Implement CTR, the stream cipher mode' do
    expect(CryptUtil.ctr(Utils::Base64.decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='), 'YELLOW SUBMARINE'))
      .to eq('Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby ')
  end

  context 'Challenge 19: Break fixed-nonce CTR mode using substitutions', :frequency_analysis => true do
    it 'decrypts within a margin of error of 10 characters (case-insensitive)' do
      key = seeded_rng.bytes(16)
      texts = path_to('data/challenge19.txt').open.each_line.map(&Utils::Base64.method(:decode))
      ciphertexts = texts.map { |text| CryptUtil.ctr(text, key) }
      case_char_distance = proc { |s1, s2| s1.chars.zip(s2.chars).reject { |c1, c2| c1.casecmp(c2).zero? }.size }
      expect(Set3.challenge19(ciphertexts).zip(texts).sum(&case_char_distance)).to be <= 10
    end
  end

end

