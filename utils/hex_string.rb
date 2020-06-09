require_relative 'string_util'

module Utils
  module HexString

    def from_bytes(bytes)
      bytes.map { |b| format("%02x", b) }.join.extend(HexString)
    end

    module_function :from_bytes

    def ^(other)
      chars.zip(other.chars).map{ |a, b| (a.hex ^ b.hex).to_s(16) }.join.extend(HexString)
    end

    def to_ascii
      octets.map(&:chr).join
    end

    def xor_against_char(c)
      from_bytes(octets.map { |n| n ^ c.ord })
    end

    def octets
      dup.prepend(size.odd? ? '0' : '').extend(StringUtil).each_slice(2).map(&:hex)
    end

  end
end
