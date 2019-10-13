require "openssl"
require "base64"
require_relative "hex_string"
require_relative "frequency"
require_relative "vigenere"
require_relative "string_util"

module Set_1
  module_function

  # Challenge 1.1: Convert hex to base64
  def challenge1(s)
    return Base64.encode64(HexString.new(s).to_ascii)
  end

  # Challenge 1.2: Fixed XOR
  def challenge2(s_1, s_2)
    return HexString.new(s_1) ^ s_2
  end

  # Challenge 1.3: Single-byte XOR cipher
  def challenge3(s)
    (0...256).each.map { |c| HexString.new(s).xor_against_char(c).to_ascii }.min_by { |s| Frequency.english_score(s) }
  end

  # Challenge 1.4: Detect single-character XOR
  def challenge4(filename)
    min_english_score = proc { |s| (0...256).each.map { |c| Frequency.english_score(HexString.new(s).xor_against_char(c).to_ascii) }.min }
    return File.new(filename).each_line.map { |line| line.strip }.min_by { |s| min_english_score.call(s.strip) }
  end

  # Challenge 1.5: Implement repeating-key XOR
  def challenge5(s, k)
    return Vigenere.xor(s, k)
  end

  # Break repeating-key XOR
  def challenge6(filename)
    ciphertext = Base64.decode64(File.readlines(filename).map(&:rstrip).join)
    key_sizes = (2..40).min_by(10) do |n|
      a = StringUtil.hamming(ciphertext[0, n], ciphertext[n, n]) / n.to_f
      b = StringUtil.hamming(ciphertext[2*n, n], ciphertext[3*n, n]) / n.to_f
      (a + b) / 2
    end

    return key_sizes.map { |n| Vigenere.decrypt(ciphertext, n) }
      .min_by { |s| Frequency.english_score(s) }
  end

  def challenge7(filename, key)
    ciphertext = Base64.decode64(File.open(filename, &:read))
    cipher = OpenSSL::Cipher::AES.new(128, :ECB)
    cipher.send(:decrypt)
    cipher.key = key
    cipher.padding = 0
    return cipher.update(ciphertext) + cipher.final
  end

  def challenge8(filename, block_size)
    return File.new(filename).each_line.to_a.max_by do |line|
      ciphertext = HexString.new(line.rstrip).to_ascii
      blocks = (0...ciphertext.length).map { |i| ciphertext[i, block_size] }
      blocks.map { |s| blocks.count(s) }.max
    end
  end

end
