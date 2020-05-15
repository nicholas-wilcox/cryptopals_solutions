require 'pathname'

module Helpers

  def path_to(filename)
    Pathname.new(__dir__) + filename
  end

  def seeded_rng
    Random.new(RSpec.configuration.seed)
  end

end
