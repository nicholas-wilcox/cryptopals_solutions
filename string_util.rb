module StringUtil
  module_function

  def hamming(s1, s2)
    return s1.each_byte.map.with_index { |b, i| b ^ s2.bytes[i] }
      .map { |byte| (0...8).map { |n| byte[n] }.sum }
      .sum
  end
end
