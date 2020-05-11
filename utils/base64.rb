require_relative 'integer_util'
require_relative 'string_util'

# This implementation of the Base64 encoding complies with RFC 2045, and should match input and output
# with Ruby's Base64 module's encode64 and decode64 methods.
# Notably, the encoding function introduces line breaks after every block of 60 encoded characters, and
# the decoding function ignores all non valid characters and stops decoding at the first padding character.
module Utils
  module Base64
    module_function
    
    BASE64_REF = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.freeze
    PAD = ?=.freeze

    def encode(s)
      s.bytes.each_slice(45).map do |line|
        line.each_slice(3).map do |block|
          IntegerUtil.n_tets(6, block.reduce(0) { |mem, n| (mem << 8) + n } << (3 - block.size).*(8), 4)
            .map(&BASE64_REF.method(:slice))[0, block.size + 1].join
            .concat(PAD * (3 - block.size))
        end.join.concat("\n")
      end.join
    end

    def decode(s)
      s.each_char.take_while(&PAD.method(:!=))
        .map(&BASE64_REF.method(:index)).reject(&:nil?)
        .each_slice(4).select { |block| block.size > 1 }
        .map { |block| block.reduce(0) { |mem, n| (mem << 6) + n } >> (4 - block.size).*(2) }
        .map(&IntegerUtil.method(:bytes)).flatten.map(&:chr).join
    end
  end
end
