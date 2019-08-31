module Frequency
  module_function

  PRINTABLE_ASCII_RANGE = (0x20..0x7E)
  ENGLISH_LETTER_FREQUENCY_RANKING = " etaoinshrdlcumwfgypbvkjxqz"

  def printable?(s)
    return s.each_byte.all? { |c| PRINTABLE_ASCII_RANGE.cover?(c) }
  end

  def frequencies(s)
    count = Hash.new(0)
    s.downcase.each_char { |c| count[c] += 1 }
    return count
    #return count.each_pair.sort_by { |k, v| v }.map(&:first).join() 
  end

  def english_score(s)
    #freqs = frequencies(s.downcase).keep_if { |k, v| ENGLISH_LETTER_FREQUENCY_RANKING.include? k }
    #total_letters = freqs.each_pair.map { |k, v| v }.sum
    return inversions(english_ranking(frequencies(s.downcase)))
  end

  def english_ranking(freqs)
    return freqs.keep_if { |k, v| ENGLISH_LETTER_FREQUENCY_RANKING.include? k }.each_pair.sort do |a, b|
      comp = -(a[1] <=> b[1])
      if comp.zero?
        ENGLISH_LETTER_FREQUENCY_RANKING.index(a[0]) <=> ENGLISH_LETTER_FREQUENCY_RANKING.index(b[0])
      else
        comp
      end
    end.map(&:first).join()
  end

  def inversions(s)
    count = 0
    s.each_char.with_index do |c1, i|
      s[i+1..-1].each_char.with_index do |c2|
        if ENGLISH_LETTER_FREQUENCY_RANKING.index(c1) > ENGLISH_LETTER_FREQUENCY_RANKING.index(c2)
          count += 1
        end
      end
    end
    return count
  end

end
