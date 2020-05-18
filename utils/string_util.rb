require_relative 'array_util'
require_relative 'integer_util'

module Utils
  module StringUtil

    def ^(other)
      bytes.zip(other.bytes).map { |a, b| a ^ b }
        .map(&IntegerUtil.method(:bit_sum)).sum
    end

    def replace_at(s, i)
      (self[0, i] + s + (i + s.length < length ? self[(i + s.length)...length] : "")).extend(StringUtil)
    end

    def each_slice(n)
      unpack((?a + n.to_s) * (size.to_f / n).ceil).each
    end

  end
end
