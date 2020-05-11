module Cryptanalysis
  module Frequency
    module_function

    ENGLISH_CHARACTERS = " etaonisrhdlucmfwgypbvkxjqz".freeze
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
    }.freeze
    
    def letter_frequencies(s)
      tally = Hash.new(0)
      s.downcase.each_char.select(&ENGLISH_CHARACTERS.method(:include?))
        .each { |c| tally[c] += 1 }
      tally.transform_values! { |v| v.to_f / s.size }
    end

    def english_score(s)
      freqs = letter_frequencies(s)
      ENGLISH_CHARACTER_FREQUENCIES.sum { |k, v| (freqs[k] - v).abs }
        .+ s.chars.reject(&ENGLISH_CHARACTERS.method(:include?)).size
    end

  end
end
