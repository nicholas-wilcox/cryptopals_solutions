# frozen_string_literal: true

require_relative '../../crypt_util'
require 'openssl'

RSpec.describe CryptUtil::HMAC do
  key = Random.bytes(16)
  data = Random.bytes(rand(50..100))

  it 'produces the same value as OpenSSL::HMAC when using SHA-1' do
    expect(subject.sha1(key, data)).to eq(OpenSSL::HMAC.digest('sha1', key, data))
  end
end
