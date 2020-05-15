module Utils
  module HashUtil

    def from_query(s)
      s.split(?&).map { |s| s.split(?=, 2) }.map { |k, v| [k.to_sym, v] }.to_h.extend(self)
    end

    module_function :from_query

    def to_query()
      map { |a| a.join(?=) }.join(?&)
    end

  end
end
