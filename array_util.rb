module ArrayUtil

  def bi_map(other, &block)
    each_index.map { |i| block.call(self[i], other[i]) }
  end

end

