require_relative "hex_string"

module Vigenere
  module_function

  def xor(s, k)
    return (0..s.length).step(k.length).map { |i| xor_chunk(s[i, k.length], k) }.join
  end

  def xor_chunk(s, k)
    return s.each_byte.map.with_index { |c, i| c ^ k.bytes[i] }.map(&:chr).join
  end

  def decrypt(ciphertext, key_size)
    blocks = (0...key_size).map { |i| (i...ciphertext.length).step(key_size).map { |j| ciphertext[j] }.join }
    key = (0...key_size).map { |i| (0...256).min_by { |c| Frequency.english_score(Vigenere.xor(blocks[i], c.chr)) } }.map(&:chr).join
    return xor(ciphertext, key)
  end

end
