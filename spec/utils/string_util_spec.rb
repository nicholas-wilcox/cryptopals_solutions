# frozen_string_literal: true

require_relative '../../utils'

RSpec.describe 'Utils::StringUtil' do
  it 'Computes Hamming distance between strings' do
    expect('this is a test'.dup.extend(Utils::StringUtil) ^ 'wokka wokka!!!').to eq(37)
  end

  context 'replace_at' do
    context 'replaces single character' do
      it 'at beginning' do
        expect('asdfasdf'.dup.extend(Utils::StringUtil).replace_at(?x, 0)).to eq('xsdfasdf')
      end

      it 'at middle' do
        expect('asdfasdf'.dup.extend(Utils::StringUtil).replace_at(?x, 3)).to eq('asdxasdf')
      end

      it 'at end' do
        expect('asdfasdf'.dup.extend(Utils::StringUtil).replace_at(?x, 7)).to eq('asdfasdx')
      end
    end

    context 'replaces multiple character' do
      it 'at beginning' do
        expect('asdfasdf'.dup.extend(Utils::StringUtil).replace_at('xxx', 0)).to eq('xxxfasdf')
      end

      it 'at middle' do
        expect('asdfasdf'.dup.extend(Utils::StringUtil).replace_at('xxx', 3)).to eq('asdxxxdf')
      end

      it 'at end' do
        expect('asdfasdf'.dup.extend(Utils::StringUtil).replace_at('xxx', 7)).to eq('asdfasdxxx')
      end
    end
  end
end
