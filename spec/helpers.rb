require 'pathname'

module Helpers

  def path_to(filename)
    Pathname.new(__dir__) + filename
  end

end
