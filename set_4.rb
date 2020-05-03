require_relative "crypt_util"

module Set_4
  module_function

  # Break "random access read/write" AES CTR
  def challenge25(plaintext)
    r = Random.new
    key = r.bytes(16)

    ciphertext = CryptUtil.ctr(plaintext, key)


    edit = ->(ciphertext, key, offset, newtext) do
      text = CryptUtil.ctr(ciphertext, key)
      text[offset, newtext.length] = newtext
      CryptUtil.ctr(text, key)
    end

    new_ciphertext = edit.call(ciphertext, key, 16, "HAHAHA I changed the plaintext")

    p CryptUtil.ctr(new_ciphertext, key)
  end

end
