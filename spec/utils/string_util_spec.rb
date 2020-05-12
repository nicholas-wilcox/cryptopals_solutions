# frozen_string_literal: true

require_relative '../../utils'

RSpec.describe 'Utils::StringUtil' do
  it 'Computes Hamming distance between strings' do
    expect('this is a test'.dup.extend(Utils::StringUtil) ^ 'wokka wokka!!!').to eq(37)
  end
end
