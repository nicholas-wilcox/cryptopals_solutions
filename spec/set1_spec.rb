# frozen_string_literal: true

require 'base64'
require_relative '../utils'
require_relative '../set1'
require_relative 'helpers'

RSpec.configure do |c|
  c.include Helpers
end


RSpec.describe 'Set 1' do
  it 'Encodes base64' do
    r = Random.new(RSpec.configuration.seed)
    s = r.bytes(r.rand(10..100))
    expect(Utils::Base64.encode(s)).to eq(Base64.strict_encode64(s))
  end

  it 'Decodes base64' do
    r = Random.new(RSpec.configuration.seed)
    s = r.bytes(r.rand(10..100))
    expect(Utils::Base64.decode(Base64.encode64(s))).to eq(s)
  end

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
end

