# frozen_string_literal: true

require_relative '../utils'
require_relative '../crypt_util'
require_relative '../set4'

RSpec.describe 'Set4', :focus => true do

  key = Random.bytes(16)

  it 'Challenge 25: Break "random access read/write" AES CTR' do
    # Assuming the nonce is \x00 * 16, it would just be cribbed into the edit function like the key
    text = Random.bytes(rand(100..200))
    ciphertext = CryptUtil.ctr(text, key).extend(Utils::StringUtil)

    # Attacker's random access oracle
    edit = proc do |offset, newtext|
      nonce = ("\x00" * 16).extend(Utils::StringUtil)
      q, r = offset.divmod(16)
      key_stream = q.upto((offset + newtext.length) / 16).map do |i|
        # Explicitly slice the first 16 bytes, since there's an extra block of encrypted padding
        CryptUtil.aes_128_ecb(nonce.replace_at((i % 256).chr, 8), key, :encrypt)[0, 16]
      end.join
      ciphertext.replace_at(CryptUtil.xor(newtext, key_stream[r, newtext.length]), offset)
    end

    expect(Set4.challenge25(ciphertext, edit)).to eq(text)
  end

  prefix = 'comment1=cooking%20MCs;userdata='
  suffix = ';comment2=%20like%20a%20pound%20of%20bacon'

  it 'Challenge 26: CTR bitflipping' do
    oracle = proc { |input| CryptUtil.ctr(prefix + input.gsub(/([;=])/, "'\\1'") + suffix, key) }
    is_admin = proc do |ciphertext|
      CryptUtil.ctr(ciphertext, key).split(/(?<!');(?!')/)
        .map { |s| s.split(/(?<!')=(?!')/, 2) }
        .map { |k, v| [k.to_sym, v] }.to_h[:admin] == "true"
    end

    expect(is_admin.call(Set4.challenge26(oracle))).to be_truthy
  end

  it 'Challenge 27: Recover the key from CBC with IV=Key' do
    oracle = proc { |input| CryptUtil.aes_128_cbc(prefix + input.gsub(/([;=])/, "'\\1'") + suffix, key, :encrypt, key) }
    verify = proc do |ciphertext|
      decrypted = CryptUtil.aes_128_cbc(ciphertext, key, :decrypt, key)
      if !decrypted.each_codepoint.all? { |c| c < 0x7F }
        raise Set4::InvalidPlaintextException.new(decrypted)
      end
    end

    expect(Set4.challenge27(oracle, verify)).to eq(key)
  end

  it 'Challenge 28: Implement a SHA-1 keyed MAC' do
    text = Random.bytes(rand(50..100))
    mac = CryptUtil::Digest::SHA1.mac(key, text)
    expect(CryptUtil::Digest::SHA1.authenticate_mac(mac, key, text)).to be_truthy
    expect(CryptUtil::Digest::SHA1.authenticate_mac(mac, key, text + ?A)).to be_falsy
  end

  message = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
  mac_key = IO.readlines('/usr/share/dict/words', chomp: true).sample
 
  it 'Challenge 29: Break a SHA-1 keyed MAC using length extension' do
    mac = CryptUtil::Digest::SHA1.mac(mac_key, message)
    forged_mac, forged_message = Set4.challenge29(mac, message)
    expect(forged_message).to end_with(';admin=true')
    expect(CryptUtil::Digest::SHA1.authenticate_mac(forged_mac, mac_key, forged_message)).to be_truthy
  end

  it 'Challenge 30: Break a MD4 keyed MAC using length extension' do
    mac = CryptUtil::Digest::MD4.mac(mac_key, message)
    forged_mac, forged_message = Set4.challenge30(mac, message)
    expect(forged_message).to end_with(';admin=true')
    expect(CryptUtil::Digest::MD4.authenticate_mac(forged_mac, mac_key, forged_message)).to be_truthy
  end
end
