class HexString < String

  def ^(other)
    return HexString.new(chars.map.with_index { |c, i| (c.hex ^ other[i].hex).to_s(16) }.join)
  end

  def to_ascii
    return octets.map { |n| format("%c", n) }.join
  end

  def xor_against_char(c)
    return HexString.new(octets.map { |n| n ^ c.ord }.map { |n| n.to_s(16) }.join)
  end

  def HexString.from_bytes(s)
    return HexString.new(s.each_byte.map { |b| format("%02x", b) }.join)
  end

  def octets
    return (0...length).step(2).map { |i| slice(i, 2) }.map(&:hex)
  end

end
