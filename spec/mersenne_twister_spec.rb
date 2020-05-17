# frozen_string_literal: true

require_relative '../mersenne_twister'

RSpec.describe 'MersenneTwister' do
  it 'produces the same output given the same seed' do
    mt1 = MersenneTwister.new(RSpec.configuration.seed)
    mt2 = MersenneTwister.new(RSpec.configuration.seed)
    5.times { expect(mt1.rand).to eq(mt2.rand) }
  end

  it 'produces bytes correctly' do 
    mt = MersenneTwister.new(RSpec.configuration.seed)
    10.upto(20).each { |n| expect(mt.bytes(n).bytesize).to eq(n) }
  end
end
