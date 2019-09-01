module Frequency
  module_function

  LOWERCASE_ASCII_RANGE = (0X61..0x7A)
  ENGLISH_LETTER_FREQUENCIES = {
    ?e => 0.12702,
    ?t => 0.09056,
    ?a => 0.08167,
    ?o => 0.07507,
    ?i => 0.06966,
    ?n => 0.06749,
    ?s => 0.06327,
    ?h => 0.06094,
    ?r => 0.05987,
    ?d => 0.04253,
    ?l => 0.04025,
    ?c => 0.02782,
    ?u => 0.02758,
    ?m => 0.02406,
    ?w => 0.02360,
    ?f => 0.02228,
    ?g => 0.02015,
    ?y => 0.01974,
    ?p => 0.01929,
    ?b => 0.01492,
    ?v => 0.00978,
    ?k => 0.00772,
    ?j => 0.00153,
    ?x => 0.00150,
    ?q => 0.00095,
    ?z => 0.00074
  }

  def letter_frequencies(s)
    count = Hash.new(0)
    letters_of_s = s.downcase.chars.keep_if { |c| LOWERCASE_ASCII_RANGE.include?(c.ord) }
    letters_of_s.each { |c| count[c] += 1 }
    return count.transform_values! { |v| v / letters_of_s.length.to_f }
  end

  def english_score(s)
    freqs = letter_frequencies(s)
    score = 0
    ENGLISH_LETTER_FREQUENCIES.each { |k, v| score += (freqs[k] - v).abs }
    return score
  end

end
