

module Set_2
  module_function

  def challenge9(s, block_size, encoding="ASCII-8BIT")
    offset = (-s.length % block_size)
    return (s + (offset.chr * offset)).encode(encoding)
  end

  def challenge10(filename, key, iv=("\x00" * 16))
    ciphertext = Base64.decode64(File.open(filename, &:read))
    cipher = OpenSSL::Cipher::AES.new(128, :ECB)
    cipher.send(:decrypt)
    cipher.key = key
    cipher.padding = 0

    return (0...ciphertext.length).step(16).map { |i| ciphertext[i, 16] }.map do |block|
      plaintext = cipher.update(block).bytes.map.with_index { |c, i| c ^ iv[i].ord }.map(&:chr).join
      iv = block
      plaintext
    end.join + cipher.final
  end

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
    cipher = OpenSSL::Cipher::AES.new(128, mode)
    cipher.send(:encrypt)
    if (mode == :CBC)
      cipher.iv = prng.bytes(16)
    end
    cipher.key = key
    cipher.padding = 0; # Do I need padding?
    # Encrypt data
    ciphertex = cipher.update(input) + cipher.final
    # Detect which encryption mode was used (using challenge 8 code to detect ECB)


    printf("Key: %s\n", key.bytes)
    printf("Prefix: %s\n", prefix)
    printf("Suffic: %s\n", suffix)
    printf("Plaintext: %s\n", plaintext)

  end

end