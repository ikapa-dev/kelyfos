package docsize

import "testing"

// The estimate is characters, not bytes, and this is the case that made that
// distinction matter: the generated corpus is full of em dashes, and counting
// their bytes would inflate the estimate by the width of the punctuation.
func TestTheEstimateCountsCharactersRatherThanBytes(t *testing.T) {
	dashes := "—————————— " // ten em dashes and a space: 11 runes, 31 bytes
	if got, want := len([]rune(dashes)), 11; got != want {
		t.Fatalf("the fixture is not what this test thinks: %d runes, want %d", got, want)
	}
	if len(dashes) == len([]rune(dashes)) {
		t.Fatal("the fixture has no multi-byte characters, so it proves nothing")
	}
	byRunes := Estimate(dashes)
	byBytes := int(float64(len(dashes)) / CharsPerToken)
	if byRunes >= byBytes {
		t.Errorf("estimating by bytes (%d) should exceed estimating by characters (%d); "+
			"if it does not, Estimate has started counting bytes", byBytes, byRunes)
	}
}

// A guard on the ratio itself. It is measured rather than guessed, and the
// measurements behind it are in the doc comment with the commands that produced
// them — so a change to it is a decision that needs those updated, not a tweak.
func TestTheRatioIsTheMeasuredOne(t *testing.T) {
	if CharsPerToken != 3.83 {
		t.Errorf("CharsPerToken is %v, not the measured 3.83.\n"+
			"If that is deliberate, the doc comment's provenance — cl100k_base and "+
			"o200k_base at E3-2 and again at the E4 exit — has to be re-measured with it. "+
			"A ratio whose stated provenance is of a different number is worse than no "+
			"ratio at all.", CharsPerToken)
	}
}
