module Utils
  module EnumUtil

    def repeat?
      each_cons(2).any? { |a, b| a == b }
    end

    def repeats_at
      each_cons(2).each_with_index.find(-> { [nil, nil] }) { |(a, b),| a == b }[1]
    end

    def uniq?
      map { |a| count(a) }.max == 1
    end

    def same?
      all? { |obj| obj == first }
    end

  end
end
