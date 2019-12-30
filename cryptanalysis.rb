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

end
