# Copied from https://rosettacode.org/wiki/MD4#Ruby
# Further modified to allow for user-defined initial hash and block offset in computation
# Also fixed an issue where utf-8 strings with multi-byte character would cause padding errors

require 'stringio'

module CryptUtil
  module Digest
    module MD4
      module_function

      INITIAL_STATE = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476].freeze

      # Calculates MD4 message digest of _string_. Returns binary digest.
      # For hexadecimal digest, use +*md4(str).unpack('H*')+.
      def digest(string, initial_state = INITIAL_STATE, block_offset = 0)
        # functions
        mask = (1 << 32) - 1
        f = proc {|x, y, z| x & y | x.^(mask) & z}
        g = proc {|x, y, z| x & y | x & z | y & z}
        h = proc {|x, y, z| x ^ y ^ z}
        r = proc {|v, s| (v << s).&(mask) | (v.&(mask) >> (32 - s))}
       
        # initial hash
        a, b, c, d = initial_state.dup
       
        bit_len = string.bytesize << 3

        string = string.bytes.append(0x80).map(&:chr).join
        while (string.size % 64) != 56
          string += "\0"
        end
        string = string.force_encoding('ascii-8bit') + [bit_len & mask, bit_len >> 32].pack("V2")
       
        if string.size % 64 != 0
          fail "failed to pad to correct length"
        end
       
        io = StringIO.new(string)
        block = ""
       
        # Seek past a given number of blocks
        io.seek(64 * block_offset)

        while io.read(64, block)
          x = block.unpack("V16")
       
          # Process this block.
          aa, bb, cc, dd = a, b, c, d
          [0, 4, 8, 12].each {|i|
            a = r[a + f[b, c, d] + x[i],  3]; i += 1
            d = r[d + f[a, b, c] + x[i],  7]; i += 1
            c = r[c + f[d, a, b] + x[i], 11]; i += 1
            b = r[b + f[c, d, a] + x[i], 19]
          }
          [0, 1, 2, 3].each {|i|
            a = r[a + g[b, c, d] + x[i] + 0x5a827999,  3]; i += 4
            d = r[d + g[a, b, c] + x[i] + 0x5a827999,  5]; i += 4
            c = r[c + g[d, a, b] + x[i] + 0x5a827999,  9]; i += 4
            b = r[b + g[c, d, a] + x[i] + 0x5a827999, 13]
          }
          [0, 2, 1, 3].each {|i|
            a = r[a + h[b, c, d] + x[i] + 0x6ed9eba1,  3]; i += 8
            d = r[d + h[a, b, c] + x[i] + 0x6ed9eba1,  9]; i -= 4
            c = r[c + h[d, a, b] + x[i] + 0x6ed9eba1, 11]; i += 8
            b = r[b + h[c, d, a] + x[i] + 0x6ed9eba1, 15]
          }
          a = (a + aa) & mask
          b = (b + bb) & mask
          c = (c + cc) & mask
          d = (d + dd) & mask
        end
       
        [a, b, c, d].pack("V4")
      end
      
      def mac(key, message)
        digest(key + message)
      end

      def authenticate_mac(mac, key, message)
        mac == mac(key, message)
      end
    end
  end
end
