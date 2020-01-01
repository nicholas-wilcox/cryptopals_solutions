module EnumUtil

  def repeat?
    loop do
      return true if self.next == self.peek
    end
    false
  end

  def find_repeat
    (0...size).each { |i| return i if self.next == self.peek }
  rescue StopIteration
    nil
  end

  def uniq?
    map { |a| count(a) }.max == 1
  end

end
