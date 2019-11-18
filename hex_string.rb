require_relative "array_util"

class HexString < String

  def self.from_bytes(bytes)
    new(bytes.map { |b| format("%02x", b) }.join)
  end

  def ^(other)
    HexString.new((chars.extend ArrayUtil).bi_map(other.chars) { |a, b| (a.hex ^ b.hex).to_s(16) }.join)
  end

  def to_ascii
    octets.map { |n| format("%c", n) }.join
  end

  def xor_against_char(c)
    HexString.new(octets.map { |n| n ^ c.ord }.map { |n| n.to_s(16) }.join)
  end

  def octets
    (0...length).step(2).map { |i| slice(i, 2) }.map(&:hex)
  end

end
