require_relative "crypt_util"

module Cryptanalysis
  module_function

  def vigenere_decrypt(ciphertext, key_size)
    t = ciphertext.bytes.concat([0] * (-ciphertext.bytesize % key_size)).each_slice(key_size).to_a.transpose
    key = (0...key_size)
      .map { |i| (0...256).min_by { |c| Frequency.english_score(CryptUtil.xor(t[i], c.chr).map(&:chr).join) } }
      .map(&:chr).join
    CryptUtil.xor(ciphertext, key)
  end

  #def detect_ecb_oracle_prefix_length(oracle, block_size)
  #  # TODO: Make less naive. Don't assume your input to the oracle will be the only instance of
  #  # repeated blocks
  #  pad = ?A * (3 * block_size)
  #  (0...block_size).each do |i|
  #    blocks = CryptUtil.blocks(oracle.call(pad), block_size)
  #    repeat_index = blocks.each.extend(EnumUtil).find_repeat
  #    break if repeat_index.nil?
  #    return (block_size * repeat_index) - i if blocks[repeat_index] == blocks[repeat_index + 2]
  #    pad += ?A
  #  end
  #  raise "Doesn't seem to be ECB"
  #end

  def decrypt_ecb_oracle(oracle, block_size, offset = 0)
    CryptUtil.remove_pad((offset...oracle.call('').bytesize).reduce('') do |decrypted, i|
      pad = ?A * (-i).modulo(block_size).pred.modulo(block_size)
      target_block = proc { |s| s.bytes.each_slice(block_size).to_a[i / block_size] }
      is_next_char = proc { |c| target_block.call(oracle.call(pad + decrypted + c)) == target_block.call(oracle.call(pad)) }
      decrypted + (0...256).map(&:chr).find(-> { '' }, &is_next_char)
    end)
  end

  #def decrypt_cbc_padding_oracle(padding_oracle, iv, ciphertext)
  #  #TODO: Tidy up lambdas and perhaps make execution more concise
  #  [iv, CryptUtil.blocks(ciphertext, iv.length)].flatten.extend(ArrayUtil).each_slice(2).map do |c1, c2|
  #    decrypted_c2_bytes = [0] * iv.length
  #    (1..iv.length).map do |i|
  #      c1[(1 - i)..-1] = decrypted_c2_bytes[(1 - i)..-1].map { |j| (j ^ i).chr }.join unless i == 1
  #      oracle_input_for_byte = ->(b) { c1.extend(StringUtil).replace_at(b.chr, iv.length - i) + c2 }
  #      invert_byte_at = ->(s, i) { s.extend(StringUtil).replace_at((0xFF ^ s[i].ord).chr, i) }
  #      find_byte = lambda do
  #        matches = (0...256).find_all { |j| padding_oracle.call(oracle_input_for_byte.call(j)) }
  #        if matches.length == 1
  #          matches[0]
  #        else
  #          matches.find(nil) { |j| padding_oracle.call(invert_byte_at.call(oracle_input_for_byte.call(j), iv.length - (i + 1))) }
  #        end      
  #      end

  #      lambda do |j|
  #        return " " if j.nil?
  #        decrypted_c2_bytes[-i] = j ^ i
  #        (decrypted_c2_bytes[-i] ^ c1[-i].ord).chr
  #      end.call(find_byte.call())
  #    end.reverse.join
  #  end.join
  #end

  #def mt_untemper(n)
  #  n ^= (n >> MersenneTwister::L)
  #  n ^= (n << MersenneTwister::T) & MersenneTwister::C
  #  n ^= (n << MersenneTwister::S) & MersenneTwister::B
  #  [14, 19, 21, 26, 28, 31].each do |i|
  #    n ^= n[i - 14] << i
  #  end
  #  n ^= (n >> MersenneTwister::U)
  #  0.upto(9).each { |i| n ^= n[i + 22] << i }
  #  n
  #end

end

require_relative 'cryptanalysis/frequency'
