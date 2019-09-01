require_relative "hex_string"

module Vigenere
module_function

  def xor(s, k)
    return (0..s.length).step(k.length).map { |i| xor_chunk(s[i, k.length], k) }.join
  end

  def xor_chunk(s, k)
    return s.each_byte.map.with_index { |c, i| (c ^ k[i].ord).to_s(16) }
      .map { |s| (s.length == 1 ? ?0 : '') + s }.join
  end

end
