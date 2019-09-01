require_relative "hex_string"
require_relative "frequency"
require_relative "vigenere"

module Set_1
  module_function

  # Challenge 1.1: Convert hex to base64
  def challenge1(s)
    return HexString.new(s).to_base64
  end

  # Challenge 1.2: Fixed XOR
  def challenge2(s_1, s_2)
    return HexString.new(s_1) ^ s_2
  end

  # Challenge 1.3: Single-byte XOR cipher
  def challenge3(s)
    (0...256).each.map { |c| HexString.new(s).xor_against_char(c).to_ascii }.min { |a, b| Frequency.english_score(a) <=> Frequency.english_score(b) }
  end

  # Challenge 1.4: Detect single-character XOR
  def challenge4(filename)
    min_english_score = proc { |s| (0...256).each.map { |c| Frequency.english_score(HexString.new(s).xor_against_char(c).to_ascii) }.min }
    return File.new("challenge1.4.txt").each_line.map { |line| line.strip }.min { |a, b| min_english_score.call(a.strip) <=> min_english_score.call(b.strip) }
  end

  # Challenge 1.5: Implement repeating-key XOR
  def challenge5(s, k)
    return Vigenere.xor(s, k)
  end

end
