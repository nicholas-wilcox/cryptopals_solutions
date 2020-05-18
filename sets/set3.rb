require_relative '../crypt_util'
require_relative '../utils'
require_relative '../cryptanalysis'
require_relative '../mersenne_twister'

module Set3
  module_function
  
  # Break fixed-nonce CTR mode using substitutions
  def challenge19(ciphertexts)
    max_length = ciphertexts.map(&:bytesize).max
    keystream = Array.new(max_length)
    plaintexts = [''] * ciphertexts.size
    guess = proc { |b, i| ciphertexts.map { |s| s[i] }.map { |c| c.nil? ? '' : c.ord.^(b).chr } }
    
    (0...max_length).each do |i|
      keystream[i] = (0...256).min_by do |j|
        Cryptanalysis::Frequency.english_score(plaintexts.zip(guess.call(j, i)).map { |text, c| text + c }.join)
      end
      guess.call(keystream[i], i).each_with_index { |c, i| plaintexts[i] += c }
    end

    # Second round so that the guesses for early characters can be tempered with the frequencies of the guessed latter characters.
    # and so a second order analysis can be performed
    (0...max_length).each do |i|
      second_guess = (0...256).min_by do |j|
        Cryptanalysis::Frequency.english_score(plaintexts.zip(guess.call(j, i))
          .map { |text, c| text.extend(Utils::StringUtil).replace_at(c, [i, text.size].min) }.join("\n"), max_order: 2, discount_punctuation: false)
      end
      guess.call(second_guess, i).each_with_index { |c, j| plaintexts[j] = plaintexts[j].extend(Utils::StringUtil).replace_at(c, [i, plaintexts[j].size].min) }
    end

    plaintexts
  end

  # Crack an MT19937 seed
  def challenge22(n)
    c = Time.now.to_i
    1.upto(15).map { |i| c - i }.find { |i| MersenneTwister.new(i).rand == n }
  end

  # Clone an MT19937 RNG from its output
  def challenge23(mt)
    internal_state = (0...MersenneTwister::N).map { Cryptanalysis.mt_untemper(mt.rand) }
    mt_clone = MersenneTwister.new
    mt_clone.set_state(internal_state)
    mt_clone
  end

  # Create the MT19937 stream cipher and break it
  def challenge24_part1(ciphertext, known_plaintext)
    (0...2**16).find { |g| CryptUtil.mt_cipher(ciphertext, g).end_with?(known_plaintext) }
  end

  def challenge24_part2(token)
    c = Time.now.to_i
    0.upto(100).any? { |i| MersenneTwister.new(c - i).bytes(16) == token }
  end
end
