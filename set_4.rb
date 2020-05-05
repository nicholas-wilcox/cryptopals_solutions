require_relative "crypt_util"
require_relative "string_util"
require_relative "hex_string"

module Set_4
  module_function

  # Break "random access read/write" AES CTR
  def challenge25(plaintext)
    r = Random.new
    key = r.bytes(16)
    # Assuming the nonce is \x00 * 16, it would just be cribbed into the edit function like the key
    
    ciphertext = CryptUtil.ctr(plaintext, key)

    edit = ->(ciphertext, key, offset, newtext) do
      ciphertext.extend(StringUtil)
      nonce = ("\x00" * 16).extend(StringUtil)
      q, r = offset.divmod(16)
      key_stream = q.upto((offset + newtext.length) / 16).map do |i|
        # Explicitly slice the first 16 bytes, since there's an extra block of encrypted padding
        CryptUtil.aes_128_ecb(nonce.replace_at((i % 256).chr, 8), key, :encrypt)[0, 16]
      end.join
      ciphertext.replace_at(CryptUtil.xor(newtext, key_stream[r, newtext.length]), offset)
    end

    ciphertext = edit.call(ciphertext, key, 40, "HAHAHA! I changed the fucking plaintext")

    ciphertext = edit.call(ciphertext, key, 100, "USING THIS HANDY FUNCTION")

    p CryptUtil.ctr(ciphertext, key)
  end

end
