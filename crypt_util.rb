require "openssl"
require_relative "array_util"
require_relative "frequency"
require_relative "enum_util"
require_relative "string_util"


module CryptUtil
  module_function

  def blocks(a, n)
    (0...a.length).step(n).map { |i| a[i, n] }
  end

  def xor(a, k)
    xor_proc = ->(x, i) { x ^ k[i % k.length].ord }
    case
    when a.is_a?(String)
      a.bytes.map.with_index(&xor_proc).map(&:chr).join
    when a.is_a?(Array)
      a.map.with_index(&xor_proc)
    end
  end

  def pad(s, block_size)
    ->(offset) { s + (offset.chr * offset)}.call(-(s.length + 1) % block_size + 1)
  end

  def valid_pad?(s)
    (s[-1].ord.nil? || !(1..s.length).cover?(s[-1].ord)) ? false : s[((s.length - s[-1].ord)..-1)].each_char.extend(EnumUtil).same?
  end

  def remove_pad(s)
    raise ArgumentError, "Invalid PKCS#7 padding" unless valid_pad?(s)
    s[0, s.length - s[-1].ord]
  end

  def aes_128_ecb_cipher(key, mode)
    cipher = OpenSSL::Cipher::AES.new(128, :ECB)
    cipher.send(mode)
    cipher.key = key
    cipher.padding = 0
    cipher
  end
 
  #TODO: Decouple padding operations, which can throw errors during removal, from encryption and decryption

  def aes_128_ecb(text, key, mode)
    cipher = aes_128_ecb_cipher(key, mode)
    text = pad(text, 16) if mode == :encrypt
    out = cipher.update(text) + cipher.final
    mode == :decrypt ? remove_pad(out) : out
  end

  def aes_128_cbc(text, key, mode, iv=("\x00" * 16))
    xor_against_iv = ->(s) { (s.bytes.extend ArrayUtil).bi_map(iv.bytes, &:^).map(&:chr).join }
    cipher = aes_128_ecb_cipher(key, mode)
    text = pad(text, 16) if mode == :encrypt
    out = blocks(text, 16).map do |block|
      case mode
      when :decrypt
        plaintext = xor_against_iv.call(cipher.update(block))
        iv = block
        plaintext
      when :encrypt
        ciphertext = cipher.update(xor_against_iv.call(block))
        iv = ciphertext
        ciphertext
      end
    end.join + cipher.final
    mode == :decrypt ? remove_pad(out) : out
  end

  def ctr(text, key, nonce=("\x00" * 16))
    blocks(text, 16).each_with_index.map do |block, i|
      xor(block, aes_128_ecb(nonce.extend(StringUtil).replace_at((nonce[8].ord + i).chr, 8), key, :encrypt))
    end.join
  end

end
