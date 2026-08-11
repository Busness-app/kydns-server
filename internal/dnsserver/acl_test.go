package dnsserver

import (
	"net/netip"
	"testing"
	"time"
)

func prefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestACLAllowsListedAndRefusesOthers(t *testing.T) {
	a := NewACL(prefixes(t, "192.168.0.0/16", "127.0.0.0/8"))
	for in, want := range map[string]bool{
		"192.168.1.5":     true,
		"127.0.0.1":       true,
		"8.8.8.8":         false,
		"100.101.102.103": false,
	} {
		if got := a.Allow(netip.MustParseAddr(in)); got != want {
			t.Errorf("Allow(%s) = %v, want %v", in, got, want)
		}
	}
}

// A dual-stack listener reports v4 peers as ::ffff:a.b.c.d.
func TestACLUnmapsV4InV6(t *testing.T) {
	a := NewACL(prefixes(t, "192.168.1.0/24"))
	if !a.Allow(netip.MustParseAddr("::ffff:192.168.1.5")) {
		t.Error("v4-mapped address refused, want allowed")
	}
}

func TestACLCountsRefusalsAndBucketsCGNAT(t *testing.T) {
	a := NewACL(prefixes(t, "192.168.0.0/16"))
	a.Allow(netip.MustParseAddr("192.168.1.5"))   // allowed, not counted
	a.Allow(netip.MustParseAddr("8.8.8.8"))       // refused, not CGNAT
	a.Allow(netip.MustParseAddr("100.64.0.1"))    // refused, CGNAT
	a.Allow(netip.MustParseAddr("100.127.255.1")) // refused, CGNAT

	s := a.Stats()
	if s.Total != 3 {
		t.Errorf("Total = %d, want 3", s.Total)
	}
	if s.CGNAT != 2 {
		t.Errorf("CGNAT = %d, want 2", s.CGNAT)
	}
	if s.LastCGNAT == 0 {
		t.Error("LastCGNAT = 0, want a timestamp")
	}
}

// 100.128.0.1 is outside 100.64.0.0/10 and must not land in the CGNAT bucket.
func TestACLCGNATBoundary(t *testing.T) {
	a := NewACL(nil)
	a.Allow(netip.MustParseAddr("100.128.0.1"))
	if s := a.Stats(); s.CGNAT != 0 {
		t.Errorf("CGNAT = %d for an address outside the range, want 0", s.CGNAT)
	}
}

func TestRecentCGNATRefusal(t *testing.T) {
	a := NewACL(nil)
	if a.RecentCGNATRefusal(time.Hour) {
		t.Error("RecentCGNATRefusal() = true with no refusals")
	}
	a.Allow(netip.MustParseAddr("100.64.0.1"))
	if !a.RecentCGNATRefusal(time.Hour) {
		t.Error("RecentCGNATRefusal() = false right after a refusal")
	}
	if a.RecentCGNATRefusal(0) {
		t.Error("RecentCGNATRefusal(0) = true, want false for a zero window")
	}
}

func TestEmptyACLRefusesEverything(t *testing.T) {
	if NewACL(nil).Allow(netip.MustParseAddr("192.168.1.1")) {
		t.Error("empty ACL allowed a query, want default-closed")
	}
}

// An unmasked prefix in the allow list must still cover its whole network.
func TestACLMasksPrefixes(t *testing.T) {
	a := NewACL(prefixes(t, "192.168.1.5/24"))
	if !a.Allow(netip.MustParseAddr("192.168.1.99")) {
		t.Error("unmasked allow prefix did not cover its network")
	}
}

// An invalid source address is refused rather than panicking.
func TestACLRefusesInvalidAddr(t *testing.T) {
	a := NewACL(prefixes(t, "0.0.0.0/0"))
	if a.Allow(netip.Addr{}) {
		t.Error("Allow(invalid) = true, want false")
	}
}
