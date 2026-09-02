package zone

import (
	"net/netip"
	"testing"

	"github.com/Busness-app/kydns-server/internal/store"
)

func TestMatcherLongestPrefixWins(t *testing.T) {
	m, err := NewMatcher([]store.View{
		{Name: "lab", Subnets: []string{"192.168.0.0/16"}},
		{Name: "rack", Subnets: []string{"192.168.7.0/24"}},
		{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		"192.168.7.9":     "rack",
		"192.168.9.9":     "lab",
		"100.101.102.103": "tailnet",
		"10.0.0.1":        "",
		"8.8.8.8":         "",
	} {
		if got := m.Match(netip.MustParseAddr(in)); got != want {
			t.Errorf("Match(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestMatcherIPv6(t *testing.T) {
	m, err := NewMatcher([]store.View{{Name: "ula", Subnets: []string{"fd00::/8"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Match(netip.MustParseAddr("fd00::1")); got != "ula" {
		t.Errorf("Match(fd00::1) = %q, want ula", got)
	}
	if got := m.Match(netip.MustParseAddr("2001:db8::1")); got != "" {
		t.Errorf("Match(2001:db8::1) = %q, want empty", got)
	}
}

// A v4-mapped v6 source address must match a v4 view: UDP sockets on a
// dual-stack listener hand back ::ffff:192.168.1.5 rather than 192.168.1.5.
func TestMatcherUnmapsV4InV6(t *testing.T) {
	m, err := NewMatcher([]store.View{{Name: "lan", Subnets: []string{"192.168.1.0/24"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Match(netip.MustParseAddr("::ffff:192.168.1.5")); got != "lan" {
		t.Errorf("Match(v4-mapped) = %q, want lan", got)
	}
}

func TestMatcherRejectsDuplicateCIDR(t *testing.T) {
	_, err := NewMatcher([]store.View{
		{Name: "a", Subnets: []string{"10.0.0.0/8"}},
		{Name: "b", Subnets: []string{"10.0.0.0/8"}},
	})
	if err == nil {
		t.Fatal("NewMatcher() error = nil, want duplicate CIDR error")
	}
}

func TestMatcherEmpty(t *testing.T) {
	m, err := NewMatcher(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Match(netip.MustParseAddr("192.168.1.1")); got != "" {
		t.Errorf("Match() on empty matcher = %q, want empty", got)
	}
}

func TestMatcherNames(t *testing.T) {
	m, err := NewMatcher([]store.View{
		{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}},
		{Name: "lab", Subnets: []string{"192.168.0.0/16"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := m.Names()
	if len(got) != 2 || got[0] != "lab" || got[1] != "tailnet" {
		t.Errorf("Names() = %v, want sorted [lab tailnet]", got)
	}
}

func TestMatcherRejectsBadCIDR(t *testing.T) {
	if _, err := NewMatcher([]store.View{{Name: "x", Subnets: []string{"not-a-cidr"}}}); err == nil {
		t.Fatal("NewMatcher() error = nil, want a parse error")
	}
}

// An unmasked CIDR like 192.168.1.5/24 must still match its whole network.
func TestMatcherMasksPrefixes(t *testing.T) {
	m, err := NewMatcher([]store.View{{Name: "lan", Subnets: []string{"192.168.1.5/24"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Match(netip.MustParseAddr("192.168.1.99")); got != "lan" {
		t.Errorf("Match() = %q, want lan for an unmasked view prefix", got)
	}
}
