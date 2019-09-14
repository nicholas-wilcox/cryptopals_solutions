module Base64
  module_function

  BASE64_REF = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  BASE64_PAD = ?=

  def encode(s)
    return s.chars.each_slice(3).map do |s|
      padding = 3 - s.length
      bits = s.map.with_index { |c, i| c.ord << ((2 - i)*8) }.sum

      format("%c%c%c%c",
             BASE64_REF[(bits & 0xFC0000) >> 18],
             BASE64_REF[(bits & 0x3F000) >> 12],
             (padding > 1 ? BASE64_PAD : BASE64_REF[(bits & 0xFC0) >> 6]),
             (padding > 0 ? BASE64_PAD : BASE64_REF[bits & 0x3F]))
    end.join
  end

  def decode(s)
    return s.chars.each_slice(4).map do |s|
      padding = s.count(BASE64_PAD)
      bits = s.delete_if { |c| c == BASE64_PAD }.map.with_index { |c, i| BASE64_REF.index(c) << ((3 - i)*6) }.sum
      format("%c%c%c",
             (bits & 0xFF0000) >> 16,
             (padding > 1 ? BASE64_PAD : (bits & 0xFF00) >> 8),
             (padding > 0 ? BASE64_PAD : (bits & 0xFF)))[0, 3 - padding]
    end.join
  end

end
