module Frequency
  module_function

  ENGLISH_CHARACTERS = " etaonisrhdlucmfwgypbvkxjqz"
  # From https://web.archive.org/web/20170918020907/http://www.data-compression.com/english.html
  ENGLISH_CHARACTER_FREQUENCIES = {
    ' ' => 0.1918182,
    ?e => 0.1041442,
    ?t => 0.0729357,
    ?a => 0.0651738,
    ?o => 0.0596302,
    ?n => 0.0564513,
    ?i => 0.0558094,
    ?s => 0.0515760,
    ?r => 0.0497563,
    ?h => 0.0492888,
    ?d => 0.0349835,
    ?l => 0.0331490,
    ?u => 0.0225134,
    ?c => 0.0217339,
    ?m => 0.0202124,
    ?f => 0.0197881,
    ?w => 0.0171272,
    ?g => 0.0158610,
    ?y => 0.0145984,
    ?p => 0.0137645,
    ?b => 0.0124248,
    ?v => 0.0082903,
    ?k => 0.0050529,
    ?x => 0.0013692,
    ?j => 0.0009033,
    ?q => 0.0008606,
    ?z => 0.0007836
  }
  
  def letter_frequencies(s)
    count = Hash.new(0)
    letters_of_s = s.downcase.chars.keep_if { |c| ENGLISH_CHARACTERS.include?(c) }
    letters_of_s.each { |c| count[c] += 1 }
    return count.transform_values! { |v| v / letters_of_s.length.to_f }
  end

  def english_score(s)
    freqs = letter_frequencies(s)
    score = 0
    ENGLISH_CHARACTER_FREQUENCIES.each { |k, v| score += (freqs[k] - v).abs }
    return score
  end

end
