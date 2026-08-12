package policy

import "testing"

func TestNormalizeCanonicalizes(t *testing.T) {
	cases := map[string]string{
		"ads.example":      "ads.example",
		"ADS.Example":      "ads.example",
		"ads.example.":     "ads.example",
		"  ads.example  ":  "ads.example",
		"a.b.c.example":    "a.b.c.example",
		"bücher.example":   "xn--bcher-kva.example",
		"xn--bcher-kva.ex": "xn--bcher-kva.ex",
	}
	for in, want := range cases {
		got, err := Normalize(in)
		if err != nil {
			t.Errorf("Normalize(%q) errored: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeRejectsJunk(t *testing.T) {
	for _, in := range []string{
		"", ".", "..", "example..com", "-ads.example", "ads-.example",
		"ads.example/path", "ads example", "*.example", "192.168.1.1",
		"2001:db8::1", "http://ads.example",
	} {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q, want an error", in, got)
		}
	}
}

func TestNormalizeRejectsOverlongNames(t *testing.T) {
	long := ""
	for i := 0; i < 10; i++ {
		long += "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz."
	}
	if _, err := Normalize(long + "example"); err == nil {
		t.Error("Normalize() accepted a name over 253 characters")
	}
	if _, err := Normalize("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz1234.example"); err == nil {
		t.Error("Normalize() accepted a label over 63 characters")
	}
}
