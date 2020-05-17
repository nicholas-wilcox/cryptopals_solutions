# frozen_string_literal: true

require_relative '../utils'
require_relative '../crypt_util'
require_relative '../set4'

RSpec.describe 'Set4', :focus => true do

  key = Random.bytes(16)

  it 'Challenge 25: Break "random access read/write" AES CTR' do
    # Assuming the nonce is \x00 * 16, it would just be cribbed into the edit function like the key
    text = Random.bytes(rand(100..200))
    ciphertext = CryptUtil.ctr(text, key).extend(Utils::StringUtil)

    # Attacker's random access oracle
    edit = proc do |offset, newtext|
      nonce = ("\x00" * 16).extend(Utils::StringUtil)
      q, r = offset.divmod(16)
      key_stream = q.upto((offset + newtext.length) / 16).map do |i|
        # Explicitly slice the first 16 bytes, since there's an extra block of encrypted padding
        CryptUtil.aes_128_ecb(nonce.replace_at((i % 256).chr, 8), key, :encrypt)[0, 16]
      end.join
      ciphertext.replace_at(CryptUtil.xor(newtext, key_stream[r, newtext.length]), offset)
    end

    expect(Set4.challenge25(ciphertext, edit)).to eq(text)
  end

  it 'Challenge 26: CTR bitflipping' do
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    oracle = proc { |input| CryptUtil.ctr(prefix + input.gsub(/([;=])/, "'\\1'") + suffix, key) }
    is_admin = proc do |ciphertext|
      CryptUtil.ctr(ciphertext, key).split(/(?<!');(?!')/)
        .map { |s| s.split(/(?<!')=(?!')/, 2) }
        .map { |k, v| [k.to_sym, v] }.to_h[:admin] == "true"
    end

    expect(is_admin.call(Set4.challenge26(oracle))).to be_truthy
  end
end
