package policy

import (
	"strings"
	"testing"
)

func TestParseDomainsFormat(t *testing.T) {
	in := `
# a comment
ads.example

  Tracker.Test  
192.168.1.1
not a domain
ads.example
`
	got, err := Parse(strings.NewReader(in), FormatDomains)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ads.example", "tracker.test"}
	if strings.Join(got.Domains, ",") != strings.Join(want, ",") {
		t.Errorf("Domains = %v, want %v", got.Domains, want)
	}
	// The IP address and the malformed line are counted, not silently dropped.
	if got.Skipped != 2 {
		t.Errorf("Skipped = %d, want 2", got.Skipped)
	}
}

func TestParseHostsFormat(t *testing.T) {
	in := `
127.0.0.1 localhost
127.0.0.1 localhost.localdomain
255.255.255.255 broadcasthost
::1 ip6-localhost ip6-loopback
0.0.0.0 ads.example
0.0.0.0 a.test b.test
0.0.0.0
garbage line
`
	got, err := Parse(strings.NewReader(in), FormatHosts)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.test", "ads.example", "b.test"}
	if strings.Join(got.Domains, ",") != strings.Join(want, ",") {
		t.Errorf("Domains = %v, want %v", got.Domains, want)
	}
	if got.Skipped == 0 {
		t.Error("Skipped = 0, want the localhost, broadcast and malformed lines counted")
	}
}

func TestParseAdblockFormat(t *testing.T) {
	in := `
! a comment
||ads.example^
||tracker.test^
@@||good.example^
||ads.example^$third-party
example.com##.banner
/some/path
||bad_
`
	got, err := Parse(strings.NewReader(in), FormatAdblock)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ads.example", "tracker.test"}
	if strings.Join(got.Domains, ",") != strings.Join(want, ",") {
		t.Errorf("Domains = %v, want %v", got.Domains, want)
	}
	// An exception rule is not an allow rule: it is unsupported and skipped.
	if got.Skipped < 4 {
		t.Errorf("Skipped = %d, want the exception, modifier, cosmetic and path rules counted", got.Skipped)
	}
}

func TestParseRejectsAnUnknownFormat(t *testing.T) {
	if _, err := Parse(strings.NewReader("ads.example"), "regex"); err == nil {
		t.Error("Parse() accepted an unknown format")
	}
}

// The ceiling is exercised through parseLimit rather than by building a
// two-million-line fixture, which would cost seconds and a gigabyte to prove
// one comparison.
func TestParseRefusesAListPastTheEntryCeiling(t *testing.T) {
	in := "a.example\nb.example\nc.example\nd.example\n"
	if _, err := parseLimit(strings.NewReader(in), FormatDomains, 2); err == nil {
		t.Error("parseLimit() accepted a list past the entry ceiling")
	}
}

func TestValidFormat(t *testing.T) {
	for _, f := range []string{FormatDomains, FormatHosts, FormatAdblock} {
		if !ValidFormat(f) {
			t.Errorf("ValidFormat(%q) = false", f)
		}
	}
	if ValidFormat("regex") {
		t.Error("ValidFormat(\"regex\") = true")
	}
}
