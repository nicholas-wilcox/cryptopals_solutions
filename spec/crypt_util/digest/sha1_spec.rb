# frozen_string_literal: true

require_relative '../../../crypt_util'
require 'openssl'


RSpec.describe CryptUtil::Digest::SHA1 do

  text = Random.bytes(rand(50..100))

  it 'produces the same hash as OpenSSL::Digest::SHA1' do
    expect(subject.digest(text)).to eq(OpenSSL::Digest::SHA1.digest(text))
  end

  it 'produces same hash regardless of encoding' do
    ascii_text = text.dup.force_encoding(Encoding::ASCII_8BIT)
    utf8_text = text.dup.force_encoding(Encoding::UTF_8)
    expect(subject.digest(ascii_text)).to eq(subject.digest(utf8_text))
  end

end
