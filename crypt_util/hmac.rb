require_relative 'digest'

module CryptUtil
  module HMAC
    module_function

    def digest(key, message, hash, block_size, output_size)
      key = hash.call(key) if key.bytesize > block_size
      key += "\x00" * (block_size - key.bytesize)

      o_key_pad = CryptUtil.xor(key, 0x5c.chr)
      i_key_pad = CryptUtil.xor(key, 0x36.chr)

      hash.call(o_key_pad + hash.call(i_key_pad + message))
    end

    def sha1(key, message)
      digest(key, message, Digest::SHA1.method(:digest).to_proc, 64, 20)
    end
  end
end
