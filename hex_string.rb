class HexString < String

  BASE64_REF = "ABCEDFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  BASE64_PAD = "="

  def to_base64
    return chars.each_slice(6).map(&:join).map do |s|
      padding = 6 - s.length
      bits = s.hex << (padding * 4)

      format("%c%c%c%c",
             BASE64_REF[(bits & 0xFC0000) >> 18],
             BASE64_REF[(bits & 0x3F000) >> 12],
             (padding / 2 > 1 ? BASE64_PAD : BASE64_REF[(bits & 0xFC0) >> 6]),
             (padding / 2 > 0 ? BASE64_PAD : BASE64_REF[bits & 0x3F]))
    end.join()
  end

  def ^(other)
    return HexString.new(chars.map.with_index.each { |c, i| (c.hex ^ other[i].hex).to_s(16) }.join())
  end

  def to_ascii
    return octets.map { |n| format("%c", n) }.join()
  end

  def xor(c)
    return HexString.new(octets.map { |n| n ^ c.ord }.map { |n| n.to_s(16) }.join())
  end

  protected

  def octets
    return chars.each_slice(2).map(&:join).map(&:hex)
  end

end
