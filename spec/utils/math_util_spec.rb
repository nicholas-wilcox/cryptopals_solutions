# frozen_string_literal: true

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
end
