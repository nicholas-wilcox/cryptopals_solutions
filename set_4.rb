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

    # Attacker's random access oracle
    edit = ->(offset, newtext) do
      ciphertext.extend(StringUtil)
      nonce = ("\x00" * 16).extend(StringUtil)
      q, r = offset.divmod(16)
      key_stream = q.upto((offset + newtext.length) / 16).map do |i|
        # Explicitly slice the first 16 bytes, since there's an extra block of encrypted padding
        CryptUtil.aes_128_ecb(nonce.replace_at((i % 256).chr, 8), key, :encrypt)[0, 16]
      end.join
      ciphertext.replace_at(CryptUtil.xor(newtext, key_stream[r, newtext.length]), offset)
    end

    key_stream = edit.call(0, "\x00" * ciphertext.length)
    CryptUtil.xor(ciphertext, key_stream)
  end

  # CTR bitflipping
  def challenge26
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    key = Random.new.bytes(16)

    oracle = ->(input) { CryptUtil.ctr(prefix + input.gsub(/([;=])/, "'\\1'") + suffix, key) }
    is_admin = lambda do |ciphertext|
      CryptUtil.ctr(ciphertext, key).split(/(?<!');(?!')/)
        .map { |s| s.split(/(?<!')=(?!')/, 2) }
        .map { |k, v| [k.to_sym, v] }.to_h[:admin] == "true"
    end
  
    payload = "asdfXadminXtrue"
    test_payload = ?A * payload.length
    test_ciphertext = oracle.call(test_payload)
    null_ciphertext = oracle.call("\x00" * payload.length)

    offset = CryptUtil.xor(null_ciphertext, test_ciphertext).index(test_payload)
    key_stream = null_ciphertext[offset, payload.length]

    ciphertext = oracle.call(payload).extend(StringUtil)
      .replace_at((key_stream[4].ord ^ ?;.ord).chr, offset + 4)
      .replace_at((key_stream[10].ord ^ ?=.ord).chr, offset + 10)

    is_admin.call(ciphertext)
  end

end
