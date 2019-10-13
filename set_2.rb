

module Set_2
  module_function

  def challenge9(s, block_size, encoding="ASCII-8BIT")
    offset = (-s.length % block_size)
    return (s + (offset.chr * offset)).encode(encoding)
  end


end
