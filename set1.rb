#require "openssl"
require_relative 'utils'
#require_relative "string_util"
require_relative 'cryptanalysis'

module Set1
  module_function

  # Convert hex to base64
  def challenge1(s)
    Utils::Base64.encode(s.extend(Utils::HexString).to_ascii)
  end

  # Fixed XOR
  def challenge2(s_1, s_2)
    s_1.extend(Utils::HexString) ^ s_2
  end

  # Single-byte XOR cipher
  def challenge3(s)
    h = s.dup.extend(Utils::HexString)
    (0...256).map { |c| h.xor_against_char(c).to_ascii }
      .min_by(&Cryptanalysis::Frequency.method(:english_score))
  end

  # Detect single-character XOR (input file is comprised of hexstrings)
  def challenge4(file)
    file.each_line.map(&:chomp).map(&method(:challenge3)).min_by(&Cryptanalysis::Frequency.method(:english_score))
  end

  ## Implement repeating-key XOR (output in example is a hexstring)
  #def challenge5(s, k)
  #  HexString.from_bytes(CryptUtil.xor(s, k).bytes)
  #end

  ## Break repeating-key XOR
  #def challenge6(filename)
  #  ciphertext = Base64.decode64(File.read(filename))
  #  key_sizes = (2..40).min_by(10) do |n|
  #    a = (ciphertext[0, n].extend StringUtil).hamming(ciphertext[n, n])
  #    b = (ciphertext[2*n, n].extend StringUtil).hamming(ciphertext[3*n, n])
  #    (a + b).to_f / (2 * n)
  #  end

  #  key_sizes.map { |n| Cryptanalysis.vigenere_decrypt(ciphertext, n) }
  #    .min_by(&Frequency.method(:english_score))
  #end

  ## AES in ECB mode (input is Base64 encoded)
  #def challenge7(filename, key)
  #  ciphertext = Base64.decode64(File.open(filename, &:read))
  #  CryptUtil.aes_128_ecb(ciphertext, key, :decrypt)
  #end

  ## Detect AES in ECB mode (ECB is stateless, so can be sussed out by noticing repeated blocks)
  #def challenge8(filename, block_size)
  #  File.new(filename).each_line.to_a.max_by do |line|
  #    ciphertext = HexString.new(line.rstrip).to_ascii
  #    blocks = (0...ciphertext.length).map { |i| ciphertext[i, block_size] }
  #    blocks.map { |s| blocks.count(s) }.max
  #  end
  #end

end
