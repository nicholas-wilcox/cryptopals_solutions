module Utils
  module IntegerUtil
    module_function

    def bytes(n, min_bytes = 1)
      n_tets(8, n, min_bytes)
    end

    def n_tets(n, m, min_tets = 1)
      [min_tets, (m.bit_length.to_f / n).ceil].max.-(1).downto(0).map { |i| (((2**n - 1) << (i * n)) & m) >> (i * n) }
    end

  end
end
