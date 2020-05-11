require_relative "crypt_util"
require_relative "array_util"
require_relative "cryptanalysis"
require_relative "hash_util"

module Set2
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
    detected_mode = Cryptanalysis.detect_ecb(ciphertext, 16) ? :ECB : :CBC

    { actual: mode, guess: detected_mode, match: mode == detected_mode }
  end
  
  # Byte-at-a-time ECB decryption (Simple)
  def challenge12(hidden_text)
    key = Random.new.bytes(16)
    oracle = ->(s) { CryptUtil.aes_128_ecb(s + hidden_text, key, :encrypt) }
    block_size = Cryptanalysis.detect_block_size(oracle)
    raise "Doesn't seem to be ECB" unless Cryptanalysis.detect_ecb(oracle, block_size)
    Cryptanalysis.decrypt_ecb_oracle(oracle, block_size)
  end

  # ECB cut-and-paste
  def challenge13()
    profile_for = ->(email) {
      { email: email.tr("&=", ""), uid: 1234, role: "user" }.extend(HashUtil).to_cookie
    }
    key = Random.new.bytes(16)
    oracle = ->(email) { CryptUtil.aes_128_ecb(profile_for.call(email), key, :encrypt) }
    decrypt_profile = ->(s) { HashUtil.from_cookie(CryptUtil.aes_128_ecb(s, key, :decrypt)) }

    pad = (?A * 10) + "admin" + (11.chr * 11)
    admin_block = oracle.call(pad)[16, 16]
    admin_profile_ciphertext = oracle.call("nhw@aol.com")[0, 32] + admin_block
    decrypt_profile.call(admin_profile_ciphertext)
  end

  # Byte-at-a-time ECB decryption (Harder)
  def challenge14(hidden_text)
    r = Random.new
    key = r.bytes(16)
    prefix = r.bytes(r.rand(2**8))
    oracle = ->(s) { CryptUtil.aes_128_ecb(prefix + s + hidden_text, key, :encrypt) }
    prefix_length = Cryptanalysis.detect_ecb_oracle_prefix_length(oracle, 16)
    Cryptanalysis.decrypt_ecb_oracle(oracle, 16, prefix_length)
  end

  # PKCS#7 padding validation
  def challenge15(s)
    CryptUtil.remove_pad(s)
  end

  # CBC bitflipping attacks
  def challenge16()
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    key = Random.new.bytes(16)

    oracle = ->(input) { CryptUtil.aes_128_cbc(prefix + input.gsub(/([;=])/, "'\\1'") + suffix, key, :encrypt) }
    is_admin = lambda do |ciphertext|
      CryptUtil.aes_128_cbc(ciphertext, key, :decrypt).split(/(?<!');(?!')/)
        .map { |s| s.split(/(?<!')=(?!')/, 2) }
        .map { |k, v| [k.to_sym, v] }.to_h[:admin] == "true"
    end

    ciphertext = oracle.call((?A * 21) + (?;.ord ^ 1).chr + "admin" + (?=.ord ^ 1).chr + "true")
    target_block = CryptUtil.blocks(ciphertext, 16)[2].bytes
    target_block[5] = target_block[5] ^ 1
    target_block[11] = target_block[11] ^ 1
    ciphertext[32, 16] = target_block.map(&:chr).join
    is_admin.call(ciphertext)
  end

end
