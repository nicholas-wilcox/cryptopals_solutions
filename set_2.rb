

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

end
