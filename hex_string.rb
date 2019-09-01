class HexString < String

  BASE64_REF = "ABCEDFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  BASE64_PAD = "="

  def ^(other)
    return HexString.new(chars.map.with_index { |c, i| (c.hex ^ other[i].hex).to_s(16) }.join())
  end

  def to_ascii
    return octets.map { |n| format("%c", n) }.join()
  end

  def xor_against_char(c)
    return HexString.new(octets.map { |n| n ^ c.ord }.map { |n| n.to_s(16) }.join())
  end

  protected

  def octets
    return chars.each_slice(2).map(&:join).map(&:hex)
  end

end
