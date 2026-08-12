package policy

import "testing"

func TestSetMatchesNameAndSubdomains(t *testing.T) {
	s := NewSet([]string{"ads.example", "tracker.test"})
	for _, name := range []string{"ads.example", "a.ads.example", "deep.a.ads.example", "tracker.test"} {
		if !s.Match(name) {
			t.Errorf("Match(%q) = false, want true", name)
		}
	}
}

// The suffix boundary is a label boundary, not a string suffix. This is the
// single most important property in the whole feature.
func TestSetDoesNotMatchAcrossLabelBoundaries(t *testing.T) {
	s := NewSet([]string{"ads.example"})
	for _, name := range []string{"badads.example", "example", "ads.example.evil", "notads.example"} {
		if s.Match(name) {
			t.Errorf("Match(%q) = true, want false", name)
		}
	}
}

func TestSetLenDeduplicates(t *testing.T) {
	s := NewSet([]string{"ads.example", "ads.example", "tracker.test"})
	if s.Len() != 2 {
		t.Errorf("Len() = %d, want 2", s.Len())
	}
}

func TestEmptySetMatchesNothing(t *testing.T) {
	if NewSet(nil).Match("ads.example") {
		t.Error("an empty set matched")
	}
}
