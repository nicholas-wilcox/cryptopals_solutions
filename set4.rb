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

  ## Implement a SHA-1 keyed MAC
  #def challenge28(mac, key, message)
  #  CryptUtil.authenticate_sha1_mac(mac, key, message)
  #end

  ## Break a SHA-1 keyed MAC using length extension
  #def challenge29
  #  # Copy SHA1 padding code into a proc
  #  sha1_pad = proc do |s|
  #    bit_len = s.bytesize << 3
  #    s.force_encoding(Encoding::ASCII_8BIT)
  #    pad = 0x80.chr
  #    while ((s + pad).size % 64) != 56
  #      pad += "\x00"
  #    end
  #    pad += [bit_len >> 32, bit_len & 0xffffffff].pack("N2")
  #  end

  #  # Message, which is known to the attacker in this case
  #  message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

  #  words = IO.readlines("/usr/share/dict/words", chomp: true)
  #  key = words.sample

  #  mac = CryptUtil.sha1_mac(key, message)
  #  h = mac.unpack("N5")

  #  extension = ";admin=true"

  #  256.times do |i|
  #    dummy_key = 0.chr * i
  #    glue = sha1_pad.call(dummy_key + message)
  #    forged_message = message + glue + extension
  #    forged_mac = SHA.sha1(dummy_key + forged_message, h, [dummy_key, message, glue].map(&:size).sum / 64)
  #    if CryptUtil.authenticate_sha1_mac(forged_mac, key, forged_message)
  #      return forged_mac, forged_message
  #    end
  #  end

  #end

  ## Break an MD4 keyed MAC using length extension
  #def challenge30
  #  md4_pad = proc do |s|
  #    bit_len = s.bytesize << 3
  #    s.force_encoding(Encoding::ASCII_8BIT)
  #    pad = 0x80.chr
  #    while ((pad.size + s.size) % 64) != 56
  #      pad += "\x00"
  #    end
  #    pad += [bit_len & ((1 << 32) - 1), bit_len >> 32].pack("V2")
  #  end

  #  # Message, which is known to the attacker in this case
  #  message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

  #  words = IO.readlines("/usr/share/dict/words", chomp: true)
  #  key = words.sample

  #  mac = CryptUtil.md4_mac(key, message)
  #  h = mac.unpack("V4")

  #  extension = ";admin=true"

  #  256.times do |i|
  #    dummy_key = 0.chr * i
  #    glue = md4_pad.call(dummy_key + message)
  #    forged_message = message + glue + extension
  #    forged_mac = MD4.md4(dummy_key + forged_message, h, [dummy_key, message, glue].map(&:size).sum / 64)
  #    if CryptUtil.authenticate_md4_mac(forged_mac, key, forged_message)
  #      return forged_mac, forged_message
  #    end
  #  end
  #end

  ## Implement and break HMAC-SHA1 with an artificial timing leak
  #def challenge31(dummy_file)
  #  server = WEBrick::HTTPServer.new({
  #    Port: 8080,
  #    Logger: WEBrick::Log.new(nil, 0),
  #    AccessLog: []
  #  })

  #  server_thread = Thread.new do
  #    trap('INT') { server.shutdown }
  #    key = Random.new.bytes(16)
  #    sig_bytes = proc { |sig| sig.unpack('a2' * (sig.size / 2)).map(&:hex) }
  #    insecure_compare = ->(s1, s2) {
  #      s1.bytes.zip(s2.bytes).each do |a, b|
  #        return false unless a == b
  #        sleep(0.05)
  #      end
  #      return true
  #    }

  #    server.mount_proc('/test') do |req, res|
  #      if insecure_compare.call(CryptUtil.hmac_sha1(key, req.query["file"]), sig_bytes.call(req.query["signature"]).map(&:chr).join)
  #        res.status = 200
  #      else
  #        res.status = 500
  #      end
  #    end

  #    server.start
  #  end

  #  Net::HTTP.start('localhost', 8080) do |http|
  #    is_ok = proc do |file, sig|
  #      http.get(format('/test?file=%s&signature=%s', file, sig)).is_a?(Net::HTTPOK)
  #    end

  #    signature = ''
  #    20.times do |i|
  #      signature += 256.times.max_by do |b|
  #        start = Time.now
  #        is_ok.call(dummy_file, (signature + b.chr).unpack1('H*'))
  #        later = Time.now
  #        (later - start)
  #      end.chr
  #    end

  #    signature.unpack1('H*')
  #  end
  #end

  ## Break HMAC-SHA1 with a slightly less artificial timing leak
  #def challenge32(dummy_file)
  #  server = WEBrick::HTTPServer.new({
  #    Port: 8080,
  #    Logger: WEBrick::Log.new(nil, 0),
  #    AccessLog: []
  #  })

  #  server_thread = Thread.new do
  #    trap('INT') { server.shutdown }
  #    key = Random.new.bytes(16)
  #    sig_bytes = proc { |sig| sig.unpack('a2' * (sig.size / 2)).map(&:hex) }
  #    insecure_compare = ->(s1, s2) {
  #      s1.bytes.zip(s2.bytes).each do |a, b|
  #        return false unless a == b
  #        sleep(0.005)
  #      end
  #      return true
  #    }

  #    server.mount_proc('/test') do |req, res|
  #      if insecure_compare.call(CryptUtil.hmac_sha1(key, req.query["file"]), sig_bytes.call(req.query["signature"]).map(&:chr).join)
  #        res.status = 200
  #      else
  #        res.status = 500
  #      end
  #    end

  #    server.start
  #  end

  #  Net::HTTP.start('localhost', 8080) do |http|
  #    is_ok = proc do |file, sig|
  #      http.get(format('/test?file=%s&signature=%s', file, sig)).is_a?(Net::HTTPOK)
  #    end

  #    signature = ''
  #    20.times do |i|
  #      signature += 256.times.max_by do |b|
  #        start = Time.now
  #        10.times { is_ok.call(dummy_file, (signature + b.chr).unpack1('H*')) }
  #        later = Time.now
  #        (later - start)
  #      end.chr
  #      p signature
  #    end

  #    if is_ok.call(dummy_file, signature.unpack1('H*'))
  #      p 'Success'
  #    end
  #  end
  #end
end
