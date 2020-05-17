require_relative 'crypt_util'
require_relative 'utils'
require_relative 'cryptanalysis'

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
          .map { |text, c| text.extend(Utils::StringUtil).replace_at(c, [i, text.size].min) }.join("\n"), 2)
      end
      guess.call(second_guess, i).each_with_index { |c, j| plaintexts[j] = plaintexts[j].extend(Utils::StringUtil).replace_at(c, [i, plaintexts[j].size].min) }
    end

    plaintexts
  end
  
  ## Implement the MT19937 Mersenne Twister RNG
  #def challenge21
  #  # See mersenne_twister.rb
  #end

  ## Crack an MT19937 seed
  #def challenge22
  #  mt = MersenneTwister.new
  #  r = Random.new

  #  # Seed mt with random, unknown time
  #  print("Waiting to seed\n")
  #  sleep(r.rand((40..1000)))
  #  s = Time.now.to_i
  #  mt.seed(s)
  #  print("Seed chosen\n")
  #  sleep(r.rand((40..1000)))

  #  n = mt.rand
  #  c = Time.now.to_i
  #  guesses = (39..1000).map { |i| c - i }
  #  guess = guesses.find { |i| mt.seed(i); mt.rand == n }
  #  printf("guess: %s, actual: %d\n", guess.to_s, s)
  #  if guess === s
  #    p 'Success!'
  #  end
  #end

  ## Clone an MT19937 RNG from its output
  #def challenge23
  #  mt = MersenneTwister.new
  #  internal_state = (0...MersenneTwister::N).map { Cryptanalysis.mt_untemper(mt.rand) }

  #  mt_clone = MersenneTwister.new
  #  mt_clone.set_state(internal_state)

  #  if 1000.times.all? { mt_clone.rand == mt.rand }
  #    p 'Success!'
  #  end
  #end

  ## Create the MT19937 stream cipher and break it
  #def challenge24
  #  p 'Part 1: Brute-force 16-bit MT stream cipher using known plaintext suffix'
  #  suffix = ?A * 14
  #  r = Random.new
  #  k = r.rand(0...2**16)
  #  plaintext = r.bytes(r.rand(10...1000)) + suffix
  #  ciphertext = CryptUtil.mt_cipher(plaintext, k)

  #  guess = (0...2**16).find { |g| CryptUtil.mt_cipher(ciphertext, g).end_with?(suffix) }

  #  printf("guess: %d, actual: %d\n", guess, k)
  #  p guess === k ? 'Success!' : 'Failure!'

  #  p 'Part 2: Detect if a password reset token was generated with MT19937 seeded with recent timestamp'

  #  mt = MersenneTwister.new
  #  c = Time.now.to_i

  #  mt.seed(c)
  #  time_token = mt.bytes(16)
  #  random_token = r.bytes(16)
  #  
  #  detect = ->(t) do
  #    mt = MersenneTwister.new
  #    mt.seed(c)
  #    t === mt.bytes(16)
  #  end

  #  p (detect.call(time_token) and !detect.call(random_token) ? 'Success' : 'Failure!')

  #end

end
