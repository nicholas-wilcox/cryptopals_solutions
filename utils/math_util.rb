module Utils
  module MathUtil
    module_function

    NEGATIVE_EXPONENT_ERROR = 'Negative exponent'

    # An implementation of modular exponentiation by squaring
    def modexp(b, e, m)
      raise ArgumentError, NEGATIVE_EXPONENT_ERROR if e < 0
      return 0 if m == 1
      (0...e.bit_length).map(&e.method(:[])).reduce([1, b]) do |(result, base), bit|
        [bit.zero? ? result : (result * base).modulo(m), (base * base).modulo(m)]
      end[0]
    end

    def invmod(a, m)
      egcd(a, m)[0].modulo(m)
    end

    def egcd(a, b)
      r0 = a
      r1 = b
      s0 = 1
      t0 = 0
      s1 = 0
      t1 = 1
      until r1.zero? do
        q1, r2 = r0.divmod(r1)
        r0, r1 = r1, r2
        s0, s1 = s1, s0 - (q1 * s1)
        t0, t1 = t1, t0 - (q1 * t1)
      end
      [s0, t0]
    end

    def crt(a, n)
      n_s = n.map { |n_i| n.reject(&n_i.method(:==)).reduce(1, &:*) }
      m = n_s.zip(n).map { |ary| invmod(*ary) }
      a.zip(m, n_s).map { |ary| ary.reduce(1, &:*) }.sum.modulo(n.reduce(1, &:*))
    end
  end
end
