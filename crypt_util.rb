require 'openssl'
require_relative 'utils'

module CryptUtil
  module_function

  INVALID_PAD_ERROR = 'Invalid PKCS#7 padding'.freeze

  def blocks(a, n)
    (0...a.size).step(n).map { |i| a[i, n] }
  end

  def xor(a, k)
    xor_byte = proc { |x, i| x ^ k[i % k.size].ord }
    case
    when a.is_a?(String)
      a.bytes.map.with_index(&xor_byte).map(&:chr).join
    when a.is_a?(Enumerable)
      a.map.with_index(&xor_byte)
    else
      nil
    end
  end

  # Implements PKCS#7 padding as per RFC 5652
  def pad(s, block_size)
    proc { |offset| s + (offset.chr * offset)}.call(-(s.size + 1) % block_size + 1)
  end

  def valid_pad?(s)
    !s[-1].nil? && !s[-1].ord.zero? && s[-1].ord <= s.size && s[s.size.-(s[-1].ord)..-1].each_char.extend(Utils::EnumUtil).same?
  end

  def remove_pad(s)
    raise ArgumentError, INVALID_PAD_ERROR unless valid_pad?(s)
    s[0, s.size - s[-1].ord]
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
    out = cipher.update(mode == :encrypt ? pad(text, 16) : text) + cipher.final
    mode == :decrypt ? remove_pad(out) : out
  end

  def aes_128_cbc(text, key, mode, iv=("\x00" * 16))
    cipher = aes_128_ecb_cipher(key, mode)
    text = pad(text, 16) if mode == :encrypt
    out = blocks(text, 16).map do |block|
      case mode
      when :decrypt
        plaintext = xor(iv, cipher.update(block))
        iv = block
        plaintext
      when :encrypt
        ciphertext = cipher.update(xor(iv, block))
        iv = ciphertext
        ciphertext
      end
    end.join + cipher.final
    mode == :decrypt ? remove_pad(out) : out
  end

  def ctr(text, key, nonce=("\x00" * 16))
    nonce.extend(Utils::StringUtil)
    text.extend(Utils::StringUtil).each_slice(16).with_index.map do |block, i|
      xor(block, aes_128_ecb(nonce.replace_at(((nonce[8].ord + i) % 256).chr, 8), key, :encrypt))
    end.join
  end

  def mt_cipher(text, key)
    CryptUtil.xor(text, MersenneTwister.new(key & 0xFFFF).bytes(text.bytesize))
  end

#  def sha1_mac(key, message)
#    SHA.sha1(key + message)
#  end
#
#  def authenticate_sha1_mac(mac, key, message)
#    sha1_mac(key, message) === mac
#  end
#
#  def md4_mac(key, message)
#    MD4.md4(key + message)
#  end
#
#  def authenticate_md4_mac(mac, key, message)
#    md4_mac(key, message) === mac
#  end
#
#  def hmac(key, message, hash, block_size, output_size)
#    key = hash.call(key) if key.bytesize > block_size
#    key += "\x00" * (block_size - key.bytesize)
#
#    o_key_pad = xor(key, "\x5c")
#    i_key_pad = xor(key, "\x36")
#
#    hash.call(o_key_pad + hash.call(i_key_pad + message))
#  end
#
#  def hmac_sha1(key, message)
#    hmac(key, message, SHA.method(:sha1).to_proc, 64, 20)
#  end
  
end

require_relative 'crypt_util/digest'
