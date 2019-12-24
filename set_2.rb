require_relative "crypt_util"
require_relative "array_util"

module Set_2
  module_function

  # Implement PKCS#7 padding
  def challenge9(s, block_size, encoding="ASCII-8BIT")
    CryptUtil.pad(s, block_size).encode(encoding)
  end

  # Implement CBC mode
  def challenge10(filename, key, iv=("\x00" * 16))
    ciphertext = Base64.decode64(File.open(filename, &:read))
    CryptUtil.aes_128_cbc(ciphertext, key, :decrypt, iv)
  end

  # An ECB/CBC detection oracle
  def challenge11(input)
    # Generate random AES key; 16 bytes
    prng = Random.new
    key = prng.bytes(16)
    
    # Add 5-10 bytes before and 5-10 bytes after the plaintext
    prefix = prng.bytes(prng.rand(5..10))
    suffix = prng.bytes(prng.rand(5..10))
    plaintext = prefix + input + suffix

    # Randomly select between EBC and CBC
    mode = [:ECB, :CBC][prng.rand(2)]
    
    # Encrypt data
    cipher = OpenSSL::Cipher::AES.new(128, mode)
    cipher.send(:encrypt)
    if (mode == :CBC)
      cipher.iv = prng.bytes(16)
    end
    cipher.key = key
    ciphertext = cipher.update(input) + cipher.final
    
    # Detect which encryption mode was used (using challenge 8 code to detect ECB)
    blocks = (0...ciphertext.length).step(16).map { |i| ciphertext[i, 16] }
    detected_mode  = blocks.map { |s| blocks.count(s) }.max > 1 ? :ECB : :CBC

    { actual: mode, guess: detected_mode }
  end
  
  # Byte-at-a-time ECB decryption (Simple)
  def challenge12(hidden_text)
    key = Random.new.bytes(16)
    oracle = ->(s) { CryptUtil.aes_128_ecb(CryptUtil.pad(s + hidden_text, 16), key, :encrypt) }
    # Detect block length (for posterity)
    detect_block_size = lambda do 
      pad = ""
      initial_length = oracle.call(pad).bytesize
      new_length = 0
      loop do
        pad += ?A
        new_length = oracle.call(pad).bytesize
        break if new_length > initial_length
      end
      new_length - initial_length
    end
    # Detect ECB (for posterity)
    detect_ecb = lambda do |block_size|
      ->(ciphertext) { ciphertext[0, block_size] == ciphertext[block_size, block_size] }
        .call(oracle.call(?A * (2 * block_size)))
    end
    # Check for ECB
    block_size = detect_block_size.call()
    unless detect_ecb.call(block_size)
      print "Doesn't seem to be ECB"
      return
    end
    # Decrypt hidden text from oracle
    revealed_text = ""
    (0...hidden_text.length).each do |i|
      padding = ?A * (block_size - (1 + (i % block_size)))
      target = (i / block_size) * block_size
      enc_block = oracle.call(padding)[target, block_size]
      revealed_text += (0...256).find(-> { ?A }) { |j| oracle.call(padding + revealed_text + j.chr)[target, block_size] == enc_block }.chr
    end

    revealed_text
  end

end
