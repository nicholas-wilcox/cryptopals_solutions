require_relative '../utils'

module Set6
  module_function

  def challenge41(ciphertext, e, n, decrypt_oracle)
    s = 0
    s = rand(2...n) until s.gcd(n) == 1
    fake_ciphertext = (Utils::MathUtil.modexp(s, e, n) * ciphertext) % n
    fake_plaintext = Utils::HexString.from_bytes(decrypt_oracle.call(fake_ciphertext).bytes).hex
    ((fake_plaintext * Utils::MathUtil.invmod(s, n)) % n).to_s(16).extend(Utils::HexString).to_ascii
  end

end
