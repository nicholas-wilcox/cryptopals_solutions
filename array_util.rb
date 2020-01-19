module ArrayUtil

  def bi_map(other, &block)
    each_index.map { |i| block.call(self[i], other[i]) }
  end

  def each_slice(n, &block)
    (0..(length - n)).map { |i| self[i, n] }.map(&block)
  end

end

