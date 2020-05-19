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
  end
end
