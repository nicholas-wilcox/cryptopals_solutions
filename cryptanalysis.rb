require_relative "crypt_util"
require_relative "enum_util"

module Cryptanalysis
  module_function

  def detect_block_size(oracle)
    pad = ""
    initial_length = oracle.call(pad).bytesize
    new_length = 0
    new_length = oracle.call(pad += ?A).bytesize while new_length <= initial_length
    new_length - initial_length
  end 

  def detect_ecb(oracle_or_text, block_size)
    detection = ->(text) { CryptUtil.blocks(text, block_size).each.extend(EnumUtil).repeat? }
    case
    when oracle_or_text.is_a?(Proc)
      detection.call(oracle_or_text.call(?A * (3 * block_size)))
    else
      detection.call(oracle_or_text)
    end
  end

  def detect_ecb_oracle_prefix_length(oracle, block_size)
    # TODO: Make less naive. Don't assume your input to the oracle will be the only instance of
    # repeated blocks
    pad = ?A * (3 * block_size)
    (0...block_size).each do |i|
      blocks = CryptUtil.blocks(oracle.call(pad), block_size)
      repeat_index = blocks.each.extend(EnumUtil).find_repeat
      break if repeat_index.nil?
      return (block_size * repeat_index) - i if blocks[repeat_index] == blocks[repeat_index + 2]
      pad += ?A
    end
    raise "Doesn't seem to be ECB"
  end

  def decrypt_ecb_oracle(oracle, block_size, offset = 0)
    revealed_text = ""
    (offset...oracle.call("").length).each do |i|
      padding = ?A * (block_size - (1 + (i % block_size)))
      target = (i / block_size) * block_size
      enc_block = oracle.call(padding)[target, block_size]
      revealed_text += (0...256).find(-> { "" }) { |j| oracle.call(padding + revealed_text + j.chr)[target, block_size] == enc_block }.chr
    end
    revealed_text
  end

end
