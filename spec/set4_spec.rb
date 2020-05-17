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
end
