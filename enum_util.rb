module EnumUtil

  def repeat?
    loop do
      return true if self.next == self.peek
    end
    false
  end

  def uniq?
    map { |a| count(a) }.max == 1
  end

end
