# frozen_string_literal: true

require_relative '../utils'
require_relative '../set1'
require_relative 'helpers'

RSpec.configure do |c|
  c.include Helpers
end

RSpec.describe 'Set1' do
  it 'Challenge 1: Convert hex to base64' do
    expect(Set1.challenge1('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'))
      .to eq('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')
  end

  it 'Challenge 2: Fixed XOR' do
    expect(Set1.challenge2('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965'))
      .to eq('746865206b696420646f6e277420706c6179')
  end

  it 'Challenge 3: Single-byte XOR cipher' do
    expect(Set1.challenge3('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))
      .to eq('Cooking MC\'s like a pound of bacon')
  end

  it 'Challenge 4: Detect single-character XOR' do
    expect(path_to('data/challenge4.txt').open(&Set1.method(:challenge4))).to eq("Now that the party is jumping\n")
  end

  it 'Challenge 5: Implement repeating-key XOR' do
    expect(Set1.challenge5("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", 'ICE'))
      .to eq('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')
  end

  it 'Computes Hamming distance between strings' do
    expect('this is a test'.dup.extend(Utils::StringUtil) ^ 'wokka wokka!!!').to eq(37)
  end

  it 'Challenge 6: Break repeating-key XOR' do
    expect(path_to('data/challenge6.txt').open(&Set1.method(:challenge6))).to eq(path_to('data/challenge6_solution.txt').open(&:read))
  end

  it 'Challenge 7: AES in ECB mode' do
    expect(path_to('data/challenge7.txt').open { |file| Set1.challenge7(file, 'YELLOW SUBMARINE') }).to eq(path_to('data/challenge7_solution.txt').open(&:read))
  end

  it 'Challenge 8: Detect AES in ECB mode' do
    expect(path_to('data/challenge8.txt').open(&Set1.method(:challenge8)))
      .to eq('d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a')
  end
end

