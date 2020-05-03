require_relative "crypt_util"
require_relative "array_util"
require_relative "cryptanalysis"
require_relative "hash_util"
require_relative "mersenne_twister"
require_relative "frequency"
require "base64"

module Set_3
  module_function

  # The CBC padding oracle
  def challenge17()
    strings = [
      "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
      "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
      "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
      "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
      "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
      "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
      "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
      "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
      "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
      "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ]
    prng = Random.new
    key = prng.bytes(16)
    iv = prng.bytes(16)
    random_index = prng.rand(10)
    plaintext = strings[random_index]
    get_ciphertext = ->() { CryptUtil.aes_128_cbc(plaintext, key, :encrypt, iv) }

    padding_oracle = lambda do |ciphertext|
      CryptUtil.aes_128_cbc(ciphertext, key, :decrypt, iv)
      true
    rescue ArgumentError
      false
    end

    Cryptanalysis.decrypt_cbc_padding_oracle(padding_oracle, iv, get_ciphertext.call())
  end

  # Implement CTR, stream cipher mode
  def challenge18(text, key)
    CryptUtil.ctr(text, key) 
  end

  # Break fixed-nonce CTR mode using substitutions
  def challenge19(filename)
    key = Random.new.bytes(16)
    ciphertexts = File.open(filename, &:read)
      .each_line.map { |line| CryptUtil.ctr(Base64.decode64(line), key) }
    max_length = ciphertexts.map(&:bytesize).max
    keystream = Array.new(max_length)
    plaintext_chars = ""

    (0...max_length).each do |i|
      guess_proc = ->(j) { CryptUtil.xor(ciphertexts.map { |s| s[i] }.find_all { |c| !c.nil? }.join, j.chr) }
      keystream[i] = (0...256).min_by do |j|
        Frequency.english_score(plaintext_chars + guess_proc.call(j))
      end
      plaintext_chars += guess_proc.call(keystream[i])
    end

    ciphertexts.each { |s| p CryptUtil.xor(s, keystream) }
  end

  # Break fixed-nonce CTR statistically
  def challenge20(filename)
    key = Random.new.bytes(16)
    ciphertexts = File.open(filename, &:read)
      .each_line.map { |line| CryptUtil.ctr(Base64.decode64(line), key) }
    min_length = ciphertexts.map(&:bytesize).min
    Cryptanalysis.vigenere_decrypt(ciphertexts.map { |s| s[0, min_length] }.join, min_length)
  end

  # Implement the MT19937 Mersenne Twister RNG
  def challenge21
    # See mersenne_twister.rb
  end

  # Crack an MT19937 seed
  def challenge22
    mt = MersenneTwister.new
    r = Random.new

    # Seed mt with random, unknown time
    print("Waiting to seed\n")
    sleep(r.rand((40..1000)))
    s = Time.now.to_i
    mt.seed(s)
    print("Seed chosen\n")
    sleep(r.rand((40..1000)))

    n = mt.rand
    c = Time.now.to_i
    guesses = (39..1000).map { |i| c - i }
    guess = guesses.find { |i| mt.seed(i); mt.rand == n }
    printf("guess: %s, actual: %d\n", guess.to_s, s)
    if guess === s
      p 'Success!'
    end
  end

  # Clone an MT19937 RNG from its output
  def challenge23
    mt = MersenneTwister.new
    internal_state = (0...MersenneTwister::N).map { Cryptanalysis.mt_untemper(mt.rand) }

    mt_clone = MersenneTwister.new
    mt_clone.set_state(internal_state)

    if 1000.times.all? { mt_clone.rand == mt.rand }
      p 'Success!'
    end
  end

end
