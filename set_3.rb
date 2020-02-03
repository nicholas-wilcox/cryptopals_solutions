require_relative "crypt_util"
require_relative "array_util"
require_relative "cryptanalysis"
require_relative "hash_util"

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

end
