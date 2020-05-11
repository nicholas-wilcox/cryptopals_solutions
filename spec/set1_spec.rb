require 'base64'
require_relative '../utils'
require_relative '../set1'

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
end

