# frozen_string_literal: true

require_relative '../utils'
require_relative '../set3'
require_relative '../cryptanalysis'
require_relative '../mersenne_twister'

RSpec.describe 'Set3' do

  key = Random.bytes(16)
  iv = Random.bytes(16)

  it 'Challenge 17: The CBC padding oracle' do
    text = Random.bytes(rand(50..100))
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

  context 'Challenge 19: Break fixed-nonce CTR mode using substitutions', :frequency_analysis => true, :long => true do
    it 'decrypts within a margin of error of 10 characters (case-insensitive)' do
      texts = path_to('data/challenge19.txt').open.each_line.map(&Utils::Base64.method(:decode))
      ciphertexts = texts.map { |text| CryptUtil.ctr(text, key) }
      case_char_distance = proc { |s1, s2| s1.chars.zip(s2.chars).reject { |c1, c2| c1.casecmp(c2).zero? }.size }
      expect(Set3.challenge19(ciphertexts).zip(texts).sum(&case_char_distance)).to be <= 10
    end
  end

  it 'Challenge 20: Break fixed-nonce CTR statistically', :frequency_analysis => true do
    texts = path_to('data/challenge20.txt').open.each_line.map(&Utils::Base64.method(:decode))
    min_length = texts.map(&:bytesize).min
    texts.map! { |text| text[0, min_length] }
    Cryptanalysis.vigenere_decrypt(
      texts.map { |text| CryptUtil.ctr(text, key) }.join,
      min_length,
      exception_characters: ?/
    ).extend(Utils::StringUtil).each_slice(min_length).zip(texts).each do |decrypted, original|
      expect(decrypted.casecmp(original)).to be_zero, -> { "failed case-insensitive match: \n#{original}\n#{decrypted}" }
    end
  end

  it 'Challenge 21: Implement the MT19937 Mersenne Twister RNG' do
    mt = MersenneTwister.new(RSpec.configuration.seed)
    srand(RSpec.configuration.seed)
    5.times { expect(mt.rand).to eq(rand(0...2**32)) }
  end

  it 'Challenge 22: Crack an MT19937 seed', :long => true do
    sleep(rand((4..10)))
    s = Time.now.to_i
    mt = MersenneTwister.new(s)
    sleep(rand((4..10)))
    expect(Set3.challenge22(mt.rand)).to eq(s)
  end

  it 'Challenge 23: Clone an MT19937 RNG from its output' do
    mt = MersenneTwister.new(RSpec.configuration.seed)
    mt_clone = Set3.challenge23(mt)
    5.times { expect(mt.rand).to eq(mt_clone.rand) }
  end

  context 'Challenge 24: Create the MT19937 stream cipher and break it' do
    it 'Part 1: Brute-force 16-bit MT stream cipher using known plaintext suffix' do
      known_plaintext = ?A * 14
      mt_key = rand(0...2**16)
      expect(Set3.challenge24_part1(CryptUtil.mt_cipher(Random.bytes(rand(10...1000)) + known_plaintext, mt_key), known_plaintext)).to eq(mt_key)
    end

    it 'Part 2: Detect if a password reset token was generated with MT19937 seeded with recent timestamp' do
      mt = MersenneTwister.new(Time.now.to_i)
      time_token = mt.bytes(16)
      random_token = Random.bytes(16)
      expect(Set3.challenge24_part2(time_token)).to be_truthy
      expect(Set3.challenge24_part2(random_token)).to be_falsy
    end
  end
end

