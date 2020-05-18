require_relative 'crypt_util'
require_relative 'utils'
require 'webrick'
require 'net/http'

module Set4
  module_function

  # Break "random access read/write" AES CTR
  def challenge25(ciphertext, edit_proc)
    CryptUtil.xor(ciphertext, edit_proc.call(0, "\x00" * ciphertext.bytesize))
  end

  # CTR bitflipping
  def challenge26(oracle)
    payload = 'asdfXadminXtrue'
    test_payload = ?A * payload.length
    test_ciphertext = oracle.call(test_payload)
    null_ciphertext = oracle.call("\x00" * payload.bytesize)

    offset = CryptUtil.xor(null_ciphertext, test_ciphertext).index(test_payload)
    key_stream = null_ciphertext[offset, payload.length]

    oracle.call(payload).extend(Utils::StringUtil)
      .replace_at((key_stream[4].ord ^ ?;.ord).chr, offset + 4)
      .replace_at((key_stream[10].ord ^ ?=.ord).chr, offset + 10)
  end

  class InvalidPlaintextException < RuntimeError
    attr :plaintext
    def initialize(plaintext)
      @plaintext = plaintext
    end
  end

  # Recover the key from CBC with IV=Key
  def challenge27(oracle, verify_proc)
    ciphertext = oracle.call(?A * 48)
    guess = nil
    begin
      verify_proc.call(ciphertext[0, 16] + ("\x00" * 16) + ciphertext)
    rescue InvalidPlaintextException => error
      guess = CryptUtil.xor(error.plaintext[0, 16], error.plaintext[32, 16])
    end
    guess
  end

  # Break a SHA-1 keyed MAC using length extension
  def challenge29(mac, message)
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
    
    h = mac.unpack('N5')
    extension = ';admin=true'

    IO.readlines('/usr/share/dict/words', chomp: true).each do |key|
      glue = sha1_pad.call(key + message)
      forged_message = message + glue + extension
      forged_mac = CryptUtil::Digest::SHA1.digest(key.force_encoding(Encoding::ASCII_8BIT) + forged_message, h, [key, message, glue].map(&:bytesize).sum / 64)
      if CryptUtil::Digest::SHA1.authenticate_mac(forged_mac, key, forged_message)
        return forged_mac, forged_message
      end
    end
  end

  # Break an MD4 keyed MAC using length extension
  def challenge30(mac, message)
    md4_pad = proc do |s|
      bit_len = s.bytesize << 3
      s.force_encoding(Encoding::ASCII_8BIT)
      pad = 0x80.chr
      while ((pad.size + s.size) % 64) != 56
        pad += "\x00"
      end
      pad += [bit_len & ((1 << 32) - 1), bit_len >> 32].pack("V2")
    end
    
    h = mac.unpack("V4")
    extension = ";admin=true"

    IO.readlines("/usr/share/dict/words", chomp: true).each do |key|
      glue = md4_pad.call(key + message)
      forged_message = message + glue + extension
      forged_mac = CryptUtil::Digest::MD4.digest(key.force_encoding(Encoding::ASCII_8BIT) + forged_message, h, [key, message, glue].map(&:bytesize).sum / 64)
      if CryptUtil::Digest::MD4.authenticate_mac(forged_mac, key, forged_message)
        return forged_mac, forged_message
      end
    end
  end

  # Implement and break HMAC-SHA1 with an artificial timing leak
  def challenge31(filename, port)
    Net::HTTP.start('localhost', port) do |http|
      is_ok = proc do |file, sig|
        http.get(format('/test?file=%s&signature=%s', file, sig)).is_a?(Net::HTTPOK)
      end

      20.times.reduce('') do |signature, i|
        signature + (0...256).max_by do |b|
          start = Time.now
          is_ok.call(filename, (signature + b.chr).unpack1('H*'))
          Time.now - start
        end.chr
      end
    end
  end

  # Break HMAC-SHA1 with a slightly less artificial timing leak
  def challenge32(filename, port)
    Net::HTTP.start('localhost', port) do |http|
      is_ok = proc do |file, sig|
        http.get(format('/test?file=%s&signature=%s', file, sig)).is_a?(Net::HTTPOK)
      end

      20.times.reduce('') do |signature, i|
        signature + (0...256).max_by do |b|
          start = Time.now
          10.times { is_ok.call(filename, (signature + b.chr).unpack1('H*')) }
          Time.now - start
        end.chr
      end
    end
  end
end
