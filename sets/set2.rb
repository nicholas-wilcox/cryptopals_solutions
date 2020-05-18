require_relative '../crypt_util'

module Set2
  module_function

  # An ECB/CBC detection oracle
  def challenge11(encryption_oracle)
    encryption_oracle.call(?A * 48).bytes.each_slice(16).extend(Utils::EnumUtil).repeat? ? :ECB : :CBC
  end
  
  # Byte-at-a-time ECB decryption (Simple)
  def challenge12(oracle)
    block_size = (1..Float::INFINITY).lazy.map(&0.chr.method(:*)).map(&oracle).map(&:bytesize)
      .map(&oracle.call('').bytesize.method(:-)).map(&:-@).drop_while(&:zero?).first
    raise "Doesn't seem to be ECB" unless oracle.call(?A * (3 * block_size)).bytes.each_slice(block_size).extend(Utils::EnumUtil).repeat?
    Cryptanalysis.decrypt_ecb_oracle(oracle, block_size)
  end

  # ECB cut-and-paste
  # This only works because I know the structure of the plaintext that is being decrypted.
  # Namely, I know the length of the string of the uid
  def challenge13(oracle)
    pad = (?A * 10) + "admin" + (11.chr * 11)
    oracle.call("abc@aol.com")[0, 32] + oracle.call(pad)[16, 16]
  end

  # Byte-at-a-time ECB decryption (Harder)
  def challenge14(oracle)
    block_size = (1..Float::INFINITY).lazy.map(&0.chr.method(:*)).map(&oracle).map(&:bytesize)
      .map(&oracle.call('').bytesize.method(:-)).map(&:-@).drop_while(&:zero?).first
    raise "Doesn't seem to be ECB" unless oracle.call(?A * (3 * block_size)).bytes.each_slice(block_size).extend(Utils::EnumUtil).repeat?
    prefix_length = Cryptanalysis.detect_ecb_oracle_prefix_length(oracle, block_size)
    Cryptanalysis.decrypt_ecb_oracle(oracle, block_size, prefix_length)
  end

  # CBC bitflipping attacks
  def challenge16(oracle)
    ciphertext = oracle.call((?A * 21) + (?;.ord ^ 1).chr + "admin" + (?=.ord ^ 1).chr + 'true')
    target_block = ciphertext.bytes.each_slice(16).to_a[2]
    target_block[5] = target_block[5] ^ 1
    target_block[11] = target_block[11] ^ 1
    ciphertext[32, 16] = target_block.map(&:chr).join
    ciphertext
  end

end
