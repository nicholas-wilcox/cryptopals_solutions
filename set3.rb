require_relative 'crypt_util'
require_relative 'utils'
require_relative "cryptanalysis"

module Set3
  module_function
  
  ## Implement CTR, stream cipher mode
  #def challenge18(text, key)
  #  CryptUtil.ctr(text, key) 
  #end

  ## Break fixed-nonce CTR mode using substitutions
  #def challenge19(filename)
  #  key = Random.new.bytes(16)
  #  ciphertexts = File.open(filename, &:read)
  #    .each_line.map { |line| CryptUtil.ctr(Base64.decode64(line), key) }
  #  max_length = ciphertexts.map(&:bytesize).max
  #  keystream = Array.new(max_length)
  #  plaintext_chars = ""

  #  (0...max_length).each do |i|
  #    guess_proc = ->(j) { CryptUtil.xor(ciphertexts.map { |s| s[i] }.find_all { |c| !c.nil? }.join, j.chr) }
  #    keystream[i] = (0...256).min_by do |j|
  #      Frequency.english_score(plaintext_chars + guess_proc.call(j))
  #    end
  #    plaintext_chars += guess_proc.call(keystream[i])
  #  end

  #  ciphertexts.each { |s| p CryptUtil.xor(s, keystream) }
  #end

  ## Break fixed-nonce CTR statistically
  #def challenge20(filename)
  #  key = Random.new.bytes(16)
  #  ciphertexts = File.open(filename, &:read)
  #    .each_line.map { |line| CryptUtil.ctr(Base64.decode64(line), key) }
  #  min_length = ciphertexts.map(&:bytesize).min
  #  Cryptanalysis.vigenere_decrypt(ciphertexts.map { |s| s[0, min_length] }.join, min_length)
  #end

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
