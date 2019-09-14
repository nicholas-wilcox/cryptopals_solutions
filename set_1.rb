require_relative "hex_string"
require_relative "frequency"
require_relative "vigenere"
require_relative "base64"

module Set_1
  module_function

  # Challenge 1.1: Convert hex to base64
  def challenge1(s)
    return Base64.encode(HexString.new(s).to_ascii)
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
    File.readlines(filename).each { |line| p HexString.from_bytes(Base64.decode(line.strip)) }
  end

end
