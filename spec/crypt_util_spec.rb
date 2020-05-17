# frozen_string_literal: true

require_relative '../crypt_util'

RSpec.describe 'CryptUtil' do

  context 'PKCS#7 padding' do
    text = 'asdf'
    it 'validates correct padding' do
      1.upto(16) { |i| expect(CryptUtil.valid_pad?(text + (i.chr * i))).to be_truthy }
    end

    it 'invalidates incorrect padding' do
      2.upto(16) { |i| expect(CryptUtil.valid_pad?(text + (i.chr * i.pred))).to be_falsy }
    end

    it 'invalidates the empty string' do
      expect(CryptUtil.valid_pad?('')).to be_falsy
    end

    it 'invalidate a padding of \x00' do
      expect(CryptUtil.valid_pad?(text + 0.chr)).to be_falsy
    end

    it 'produces valid padding' do
      expect(CryptUtil.valid_pad?(CryptUtil.pad(Random.bytes(rand(10..100)), rand(1..20)))).to be_truthy
    end

    it 'handles edge case of text.bytesize % block_size = 0' do
      block_size = rand(10..20)
      s = CryptUtil.pad(Random.bytes(block_size), block_size)
      expect(s[block_size, block_size]).to eq(block_size.chr * block_size)
      expect(CryptUtil.valid_pad?(s)).to be_truthy
    end

    it 'removes padding correctly' do
      s = Random.bytes(rand(10..100))
      block_size = rand(10..20)
      expect(CryptUtil.remove_pad(CryptUtil.pad(s, block_size))).to eq(s)
    end

    it 'raises ArgumentError when removing incorrect padding' do
      2.upto(16) { |i| expect { CryptUtil.remove_pad(text + (i.chr * i.pred)) }.to raise_error(ArgumentError, CryptUtil::INVALID_PAD_ERROR) }
    end
  end
end
