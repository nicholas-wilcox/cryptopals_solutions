class MersenneTwister

  W = 32
  W_MASK = 2**W - 1
  N = 624
  M = 397
  R = 31
  A = 0x9908B0DF
  U = 11
  D = 0xFFFFFFFF
  S = 7
  B = 0x9D2C5680
  T = 15
  C = 0xEFC60000
  L = 18
  F = 1812433253

  LOWER_MASK = (1 << R) - 1
  UPPER_MASK = W_MASK & ~LOWER_MASK

  def initialize()
    @mt = Array.new(N)
    @index = N + 1
    seed(Time.now.to_i)
  end

  def seed(s)
    @index = N
    @mt[0] = s & W_MASK
    (1...N).each { |i| @mt[i] = W_MASK & (F * (@mt[i - 1] ^ (@mt[i - 1] >> (W - 2))) + i) }
  end

  def rand
    if @index >= N
      if @index > N
        raise RuntimeError, 'Generator was never seeded'
      end
      twist
    end

    y = @mt[@index]
    y ^= (y >> U) & D
    y ^= (y << S) & B
    y ^= (y << T) & C
    y ^= y >> L

    @index += 1
    y & W_MASK
  end

  private

  def twist
    (0...N).each do |i|
      x = (@mt[i] & UPPER_MASK) + (@mt[(i + 1) % N] & LOWER_MASK)
      xA = x >> 1
      if (x % 2) != 0
        xA ^= A
      end
      @mt[i] = @mt[(i + M) % N] ^ xA
    end

    @index = 0
  end

end
