# frozen_string_literal: true

require 'base64'
require_relative '../../utils'
require_relative '../helpers'

RSpec.configure do |c|
  c.extend Helpers
  c.include Helpers
end

RSpec.describe 'Utils::Base64' do
  it 'Encodes base64' do
    r = seeded_rng
    s = r.bytes(r.rand(10..100))
    expect(Utils::Base64.encode(s)).to eq(Base64.strict_encode64(s))
  end

  it 'Decodes base64 (inverts Ruby\'s Base64.encode64)' do
    r = seeded_rng
    s = r.bytes(r.rand(10..100))
    expect(Utils::Base64.decode(Base64.encode64(s))).to eq(s)
  end

  it 'Decodes edge case of many null bytes' do
    null_string = 'AAAA'
    expect(Utils::Base64.decode(null_string)).to eq(Base64.decode64(null_string))
  end

  it 'Decodes base64 (matches Ruby\'s Base64.decode64 against multi-line file' do
    text = path_to('data/challenge6.txt').open(&:read)
    expect(Utils::Base64.decode(text)).to  eq(Base64.decode64(text))
  end
end
