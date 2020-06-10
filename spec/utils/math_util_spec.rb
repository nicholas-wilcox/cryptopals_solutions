# frozen_string_literal: true

require 'openssl'
require_relative '../../utils'

RSpec.describe Utils::MathUtil do
  context 'computes modular exponentiation' do
    it 'matches Integer.pow(e, m)' do
      b = rand(0...2**32)
      e = rand(0...2**32)
      m = rand(0...2**32)
      expect(subject.modexp(b, e, m)).to eq(b.pow(e, m))
    end

    it 'returns 0 when base is 0' do
      expect(subject.modexp(0, 3, 2)).to be_zero
    end

    it 'returns 1 when exponent is 0' do
      expect(subject.modexp(3, 0, 2)).to eq(1)
    end

    it 'returns 0 when modulus is 1' do
      expect(subject.modexp(rand(0..100), rand(0..100), 1)).to be_zero
    end

    it 'raises ArgumentError when given negative exponent' do
      expect { subject.modexp(3, -1, 4) }.to raise_error(ArgumentError, subject::NEGATIVE_EXPONENT_ERROR)
    end

    it 'raises ZeroDivisionError when m = 0' do
      expect { subject.modexp(3, 4, 0) }.to raise_error(ZeroDivisionError)
    end
  end

  context 'Computes gcd' do
    egcd_gcd = lambda do |a, b|
      s, t = Utils::MathUtil.egcd(a, b)
      (a * s) + (b * t)
    end
    
    a = rand(0...2**32)
    b = rand(0...2**32)

    it 'matches Integer.gcd' do
      expect(egcd_gcd.call(a, b)).to eq(a.gcd(b))
    end

    it 'matches Integer.gcd when a = 0' do
      expect(egcd_gcd.call(0, b)).to eq(0.gcd(b))
    end

    it 'matches Integer.gcd when b = 0' do
      expect(egcd_gcd.call(a, 0)).to eq(a.gcd(0))
    end
  end

  it 'Computes modular inverses' do
    p = OpenSSL::BN.generate_prime(32)
    a = rand(1...p)
    expect(Utils::MathUtil.invmod(a, p.to_i)).to eq(OpenSSL::BN.new(a).mod_inverse(p))
  end

  it 'Performs the Chinese Remainder Theorem' do
    a = [0, 3, 4]
    n = [3, 4, 5]
    expect(Utils::MathUtil.crt(a, n)).to eq(39)
  end
end
