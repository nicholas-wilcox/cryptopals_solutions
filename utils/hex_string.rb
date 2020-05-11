require_relative 'string_util'

module Utils
  class HexString < String
    include StringUtil

    def self.from_bytes(bytes)
      new(bytes.map { |b| format("%02x", b) }.join)
    end

    def ^(other)
      HexString.new(chars.zip(other.chars).map{ |a, b| (a.hex ^ b.hex).to_s(16) }.join)
    end

    def to_ascii
      octets.map(&:chr).join
    end

    def xor_against_char(c)
      HexString.new(octets.map { |n| n ^ c.ord }.map { |n| n.to_s(16) }.join)
    end

    def octets
      each_slice(2).map(&:hex)
    end

  end
end
