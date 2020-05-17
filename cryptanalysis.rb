require_relative "crypt_util"

module Cryptanalysis
  module_function

  def vigenere_decrypt(ciphertext, key_size, discount_punctuation: true, exception_characters: '')
    t = ciphertext.bytes.concat([0] * (-ciphertext.bytesize % key_size)).each_slice(key_size).to_a.transpose
    key = (0...key_size).map do |i|
      (0...256).min_by do |c|
        Frequency.english_score(CryptUtil.xor(t[i], c.chr).map(&:chr).join,
                                discount_punctuation: discount_punctuation,
                                exception_characters: exception_characters)
      end
    end.map(&:chr).join
    CryptUtil.xor(ciphertext, key)
  end

  def detect_ecb_oracle_prefix_length(oracle, block_size)
    # TODO: Make less naive. Don't assume your input to the oracle will be the only instance of
    # repeated blocks
    base_pad = ?A * (3 * block_size)
    repeat_index = oracle.call(base_pad).bytes.each_slice(block_size).extend(Utils::EnumUtil).repeats_at
    (block_size * repeat_index) - (0...block_size).find(-> { 0 }) do |i|
      blocks = oracle.call(base_pad + (?A * i)).bytes.each_slice(block_size).to_a
      blocks[repeat_index] == blocks[repeat_index + 2]
    end
  end

  def decrypt_ecb_oracle(oracle, block_size, offset = 0)
    CryptUtil.remove_pad((offset...oracle.call('').bytesize).reduce('') do |decrypted, i|
      pad = ?A * (-i).modulo(block_size).pred.modulo(block_size)
      target_block = proc { |s| s.bytes.each_slice(block_size).to_a[i / block_size] }
      is_next_char = proc { |c| target_block.call(oracle.call(pad + decrypted + c)) == target_block.call(oracle.call(pad)) }
      decrypted + (0...256).map(&:chr).find(-> { '' }, &is_next_char)
    end)
  end

  def decrypt_cbc_padding_oracle(padding_oracle, iv, ciphertext)
    CryptUtil.remove_pad(
      ciphertext.bytes.each_slice(iv.bytesize).to_a.prepend(iv.bytes).each_cons(2).map do |c1, c2|
        1.upto(iv.bytesize).reduce([]) do |decrypted_bytes, i|
          c1_prime = c1[0..-i] + decrypted_bytes.map(&i.method(:^))
          oracle_input_for_byte = proc { |b| c1_prime.values_at(0...-i, i == 1 ? 0...0 : (-i).succ..).insert(-i, b).append(*c2).map(&:chr).join }
          invert_byte_at = proc { |s, i| s.extend(Utils::StringUtil).replace_at((0xFF ^ s[i].ord).chr, i) }
          find_next_byte = proc do
            matches = (0...256).select { |j| padding_oracle.call(oracle_input_for_byte.call(j)) }
            case matches.size
            when 0
              nil
            when 1
              matches[0]
            else
              matches.find { |j| padding_oracle.call(invert_byte_at.call(oracle_input_for_byte.call(j), iv.bytesize - (i + 1))) }
            end
          end
          decrypted_bytes.prepend(i ^ find_next_byte.call)
        end.zip(c1).map { |a, b| a ^ b }.map(&:chr).join
      end.join
    )
  end

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
