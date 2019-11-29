require_relative "array_util"
require_relative "frequency"

module CryptUtil
  module_function

  def blocks(a, n)
    (0...a.length).step(n).map { |i| a[i, n] }
  end

  def xor(a, k)
    xor_proc = ->(x, i) { x ^ k[i % k.length].ord }
    case
    when a.is_a?(String)
      a.bytes.map.with_index(&xor_proc).map(&:chr).join
    when a.is_a?(Array)
      a.map.with_index(&xor_proc)
    end
  end

  def vigenere_decrypt(ciphertext, key_size)
    padding = [0] * (-ciphertext.length % key_size)
    b = blocks(ciphertext.bytes + padding, key_size).transpose
    key = (0...key_size)
      .map { |i| (0...256).min_by { |c| Frequency.english_score(xor(b[i], c.chr).map(&:chr).join) } }
      .map(&:chr).join
    xor(ciphertext, key)
  end 

end
