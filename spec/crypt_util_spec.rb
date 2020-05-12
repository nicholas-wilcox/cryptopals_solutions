# frozen_string_literal: true

require_relative '../crypt_util'

RSpec.describe 'CryptUtil' do

  context 'PKCS#7 padding' do
    text = 'asdf'
    it 'validates correct padding' do
      1.upto(16) { |i| expect(CryptUtil.valid_pad?(text + (i.chr * i))).to be true }
    end

    it 'invalidates incorrect padding' do
      2.upto(16) { |i| expect(CryptUtil.valid_pad?(text + (i.chr * i.pred))).to be false }
    end

    it 'invalidates the empty string' do
      expect(CryptUtil.valid_pad?('')).to be false
    end

    it 'produces valid padding' do
      r = Random.new(RSpec.configuration.seed)
      expect(CryptUtil.valid_pad?(CryptUtil.pad(r.bytes(r.rand(10..100)), r.rand(1..20)))).to be true
    end

    it 'handles edge case of text.bytesize % block_size = 0' do
      r = Random.new(RSpec.configuration.seed)
      block_size = r.rand(10..20)
      s = CryptUtil.pad(r.bytes(block_size), block_size)
      expect(s[block_size, block_size]).to eq(block_size.chr * block_size)
      expect(CryptUtil.valid_pad?(s)).to be true
    end

    it 'removes padding correctly' do
      r = Random.new(RSpec.configuration.seed)
      s = r.bytes(r.rand(10..100))
      block_size = r.rand(10..20)
      expect(CryptUtil.remove_pad(CryptUtil.pad(s, block_size))).to eq(s)
    end

    it 'raises ArgumentError when removing incorrect padding' do
      2.upto(16) { |i| expect { CryptUtil.remove_pad(text + (i.chr * i.pred)) }.to raise_error(ArgumentError, CryptUtil::INVALID_PAD_ERROR) }
    end
  end
end
