module Utils
  module IntegerUtil
    module_function

    def bytes(n, min_bytes = 1)
      n_tets(n, 8, min_bytes)
    end

    def n_tets(m, n, min_tets = 1)
      m.digits(2**n).concat([0] * [0, min_tets - (m.bit_length.to_f / n).ceil].max).reverse
    end

    def bit_sum(n)
      (0...n.bit_length).map(&n.method(:[])).sum
    end

  end
end
