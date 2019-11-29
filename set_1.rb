require "openssl"
require "base64"
require_relative "hex_string"
require_relative "frequency"
require_relative "string_util"

module Set_1
  module_function

  # Challenge 1.1: Convert hex to base64
  def challenge1(s)
    Base64.encode64(HexString.new(s).to_ascii)
  end

  # Challenge 1.2: Fixed XOR
  def challenge2(s_1, s_2)
    HexString.new(s_1) ^ s_2
  end

  # Challenge 1.3: Single-byte XOR cipher
  def challenge3(s)
    (0...256).map { |c| HexString.new(s).xor_against_char(c).to_ascii }.min_by { |s| Frequency.english_score(s) }
  end

  # Challenge 1.4: Detect single-character XOR
  def challenge4(filename)
    min_english_score = proc { |s| (0...256).map { |c| Frequency.english_score(HexString.new(s).xor_against_char(c).to_ascii) }.min }
    File.new(filename).each_line.map { |line| line.strip }.min_by { |s| min_english_score.call(s.strip) }
  end

  # Challenge 1.5: Implement repeating-key XOR
  def challenge5(s, k)
    HexString.from_bytes(CryptUtil.xor(s, k).bytes)
  end

  # Break repeating-key XOR
  def challenge6(filename)
    ciphertext = Base64.decode64(File.read(filename))
    key_sizes = (2..40).min_by(10) do |n|
      a = (ciphertext[0, n].extend StringUtil).hamming(ciphertext[n, n])
      b = (ciphertext[2*n, n].extend StringUtil).hamming(ciphertext[3*n, n])
      (a + b).to_f / (2 * n)
    end

    key_sizes.map { |n| CryptUtil.vigenere_decrypt(ciphertext, n) }
      .min_by(&Frequency.method(:english_score))
  end

  def challenge7(filename, key)
    ciphertext = Base64.decode64(File.open(filename, &:read))
    cipher = CryptUtil.aes_128_ecb(key, :decrypt)
    cipher.update(ciphertext) + cipher.final
  end

  def challenge8(filename, block_size)
    File.new(filename).each_line.to_a.max_by do |line|
      ciphertext = HexString.new(line.rstrip).to_ascii
      blocks = (0...ciphertext.length).map { |i| ciphertext[i, block_size] }
      blocks.map { |s| blocks.count(s) }.max
    end
  end

end
