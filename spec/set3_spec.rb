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

end

