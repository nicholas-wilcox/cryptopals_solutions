require_relative "crypt_util"
require_relative "string_util"
require_relative "hex_string"
require_relative "sha"

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

  class InvalidPlaintextException < RuntimeError
    attr :plaintext
    def initialize(plaintext)
      @plaintext = plaintext
    end
  end

  # Recover the key from CBC with IV=Key
  def challenge27
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    key = Random.new.bytes(16)

    oracle = ->(input) { CryptUtil.aes_128_cbc(prefix + input.gsub(/([;=])/, "'\\1'") + suffix, key, :encrypt, key) }
    verify = lambda do |ciphertext|
      decrypted = CryptUtil.aes_128_cbc(ciphertext, key, :decrypt, key)
      if !decrypted.each_codepoint.all? { |c| c < 0x7F }
        raise InvalidPlaintextException.new(decrypted)
      end
    end

    ciphertext = oracle.call(?A * 48)
    guess = nil
    begin
      verify.call(ciphertext[0, 16] + ("\x00" * 16) + ciphertext)
    rescue InvalidPlaintextException => error
      guess = CryptUtil.xor(error.plaintext[0, 16], error.plaintext[32, 16])
    end

    guess === key
  end

  # Implement a SHA-1 keyed MAC
  def challenge28(mac, key, message)
    CryptUtil.authenticate_sha1_mac(mac, key, message)
  end

  # Break a SHA-1 keyed MAC using length extension
  def challenge29
    # Copy SHA1 padding code into a proc
    sha1_pad = proc do |s|
      bit_len = s.bytesize << 3
      s.force_encoding(Encoding::ASCII_8BIT)
      pad = 0x80.chr
      while ((s + pad).size % 64) != 56
        pad += "\x00"
      end
      pad += [bit_len >> 32, bit_len & 0xffffffff].pack("N2")
    end

    # Message, which is known to the attacker in this case
    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

    words = IO.readlines("/usr/share/dict/words", chomp: true)
    key = words.sample

    mac = CryptUtil.sha1_mac(key, message)
    h = mac.unpack("N5")

    extension = ";admin=true"

    256.times do |i|
      dummy_key = 0.chr * i
      glue = sha1_pad.call(dummy_key + message)
      forged_message = message + glue + extension
      forged_mac = SHA.sha1(dummy_key + forged_message, h, [dummy_key, message, glue].map(&:size).sum / 64)
      if CryptUtil.authenticate_sha1_mac(forged_mac, key, forged_message)
        return forged_mac, forged_message
      end
    end

  end

end
