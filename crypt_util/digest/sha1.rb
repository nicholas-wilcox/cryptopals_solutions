# Copied from https://rosettacode.org/wiki/SHA-1#Ruby
# Further modified to allow for user-defined initial hash and block offset in computation
# Also fixed an issue where utf-8 strings with multi-byte character would cause padding errors

require 'stringio'

module CryptUtil
  module Digest
    module SHA
      module_function

      INITIAL_STATE = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0].freeze

      # Calculates SHA-1 message digest of _string_. Returns binary digest.
      # For hexadecimal digest, use +*sha1(string).unpack('H*')+.
      #--
      # This is a simple, pure-Ruby implementation of SHA-1, following
      # the algorithm in FIPS 180-1.
      #++
      def sha1(string, initial_state = INITIAL_STATE, block_offset = 0)
        # functions and constants
        mask = 0xffffffff
        s = proc{|n, x| ((x << n) & mask) | (x >> (32 - n))}
        f = [
          proc {|b, c, d| (b & c) | (b.^(mask) & d)},
          proc {|b, c, d| b ^ c ^ d},
          proc {|b, c, d| (b & c) | (b & d) | (c & d)},
          proc {|b, c, d| b ^ c ^ d},
        ].freeze
        k = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6].freeze
       
        # Use bytesize, to account for multi-byte UTF-8 characters
        bit_len = string.bytesize << 3

        # Force ascii encoding before padding for the same reason
        string = string.bytes.append(0x80).map(&:chr).join
        while (string.size % 64) != 56
          string += "\0"
        end
        string = string.force_encoding('ascii-8bit') + [bit_len >> 32, bit_len & mask].pack("N2")
       
        if string.size % 64 != 0
          fail "failed to pad to correct length"
        end

        io = StringIO.new(string)
        block = ""
       
        # Seek past a given number of blocks
        io.seek(64 * block_offset)

        # The default value is frozen and we don't want to alter the input array
        h = initial_state.dup

        while io.read(64, block)
          w = block.unpack("N16")
       
          # Process block.
          (16..79).each {|t| w[t] = s[1, w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]]}
       
          a, b, c, d, e = h
          t = 0
          4.times do |i|
            20.times do
              temp = (s[5, a] + f[i][b, c, d] + e + w[t] + k[i]) & mask
              a, b, c, d, e = temp, a, s[30, b], c, d
              t += 1
            end
          end
       
          [a,b,c,d,e].each_with_index {|x,i| h[i] = (h[i] + x) & mask}
        end
       
        h.pack("N5")
      end
    end
  end
end
