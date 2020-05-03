module IntegerUtil
  module_function

  def ith_byte(n, i)
    ((0xFF << (i * 8)) & n) >> (i * 8)
  end

  def bytes(n, min_bytes=1)
    [min_bytes - 1, (n.bit_length / 8)].max.downto(0).map { |i| ith_byte(n, i) }
  end

end
