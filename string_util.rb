require_relative "array_util"

module StringUtil

  def hamming(other)
    (bytes.extend ArrayUtil)
      .bi_map(other.bytes) { |a, b| a ^ b }
      .map { |byte| (0..8).map { |n| byte[n] }.sum }
      .sum
  end
end
