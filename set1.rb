require_relative 'utils'
require_relative 'cryptanalysis'
require_relative 'crypt_util'
require 'base64'

module Set1
  module_function

  # Convert hex to base64
  def challenge1(s)
    Utils::Base64.encode(s.dup.extend(Utils::HexString).to_ascii)
  end

  # Fixed XOR
  def challenge2(s1, s2)
    s1.dup.extend(Utils::HexString) ^ s2
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

  # Implement repeating-key XOR (input is ASCII and output is a hexstring)
  def challenge5(s, k)
    Utils::HexString.from_bytes(CryptUtil.xor(s.bytes, k))
  end

  # Break repeating-key XOR
  def challenge6(file)
    ciphertext = Utils::Base64.decode(file.read)
    (2..40).min_by(10) do |n|
      (ciphertext[0, n].extend(Utils::StringUtil) ^ ciphertext[n, n])
        .+(ciphertext[2*n, n].extend(Utils::StringUtil) ^ ciphertext[3*n, n])
        .to_f / (2 * n)
    end
      .map { |n| Cryptanalysis.vigenere_decrypt(ciphertext, n) }
      .min_by(&Cryptanalysis::Frequency.method(:english_score))
  end

  # AES in ECB mode (input is Base64 encoded)
  def challenge7(file, key)
    CryptUtil.aes_128_ecb(Utils::Base64.decode(file.read), key, :decrypt)
  end

  ## Detect AES in ECB mode (ECB is stateless, so can be sussed out by noticing repeated blocks)
  #def challenge8(filename, block_size)
  #  File.new(filename).each_line.to_a.max_by do |line|
  #    ciphertext = HexString.new(line.rstrip).to_ascii
  #    blocks = (0...ciphertext.length).map { |i| ciphertext[i, block_size] }
  #    blocks.map { |s| blocks.count(s) }.max
  #  end
  #end

end
