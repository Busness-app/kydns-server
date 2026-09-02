package policy

import (
	"testing"

	"github.com/Busness-app/kydns-server/internal/store"
)

func testSnapshot(t *testing.T, enabled bool) *Snapshot {
	t.Helper()
	return Build(
		store.BlacklistSettings{Enabled: enabled, BlockTTL: 60},
		[]store.BlacklistList{
			{Name: "steven-black", Enabled: true, Snapshot: []string{"ads.example", "shared.example"}},
			{Name: "off-list", Enabled: false, Snapshot: []string{"quiet.example"}},
		},
		[]store.BlacklistRule{
			{Kind: "deny", Domain: "banned.example"},
			{Kind: "allow", Domain: "shared.example"},
			{Kind: "deny", Domain: "evil.shared.example"},
		},
	)
}

func TestDecideBlocksAListedName(t *testing.T) {
	got := testSnapshot(t, true).Decide("ads.example")
	if !got.Blocked || got.Policy != "steven-black" || got.TTL != 60 {
		t.Errorf("Decide(ads.example) = %+v, want blocked by steven-black at 60s", got)
	}
}

func TestDecideBlocksASubdomainOfAListedName(t *testing.T) {
	if got := testSnapshot(t, true).Decide("cdn.ads.example."); !got.Blocked {
		t.Errorf("Decide(cdn.ads.example.) = %+v, want blocked", got)
	}
}

func TestDecideDoesNotBlockAcrossALabelBoundary(t *testing.T) {
	if got := testSnapshot(t, true).Decide("badads.example"); got.Blocked {
		t.Errorf("Decide(badads.example) = %+v, want forwarded", got)
	}
}

// An allow rule beats the list that would otherwise block the name.
func TestAllowRuleBeatsAList(t *testing.T) {
	got := testSnapshot(t, true).Decide("shared.example")
	if got.Blocked || got.Policy != PolicyAllow {
		t.Errorf("Decide(shared.example) = %+v, want an allow decision", got)
	}
}

// An explicit deny beats an explicit allow, even the parent allow above it.
func TestDenyRuleBeatsAnAllowRule(t *testing.T) {
	got := testSnapshot(t, true).Decide("evil.shared.example")
	if !got.Blocked || got.Policy != PolicyDeny {
		t.Errorf("Decide(evil.shared.example) = %+v, want a deny decision", got)
	}
}

func TestDenyRuleBlocksSubdomains(t *testing.T) {
	if got := testSnapshot(t, true).Decide("a.banned.example"); !got.Blocked {
		t.Errorf("Decide(a.banned.example) = %+v, want blocked", got)
	}
}

func TestDisabledListDoesNotBlock(t *testing.T) {
	if got := testSnapshot(t, true).Decide("quiet.example"); got.Blocked {
		t.Errorf("Decide(quiet.example) = %+v, want forwarded: its list is disabled", got)
	}
}

// The global toggle stops new blocks without deleting anything.
func TestDisabledPolicyBlocksNothing(t *testing.T) {
	s := testSnapshot(t, false)
	for _, n := range []string{"ads.example", "banned.example"} {
		if got := s.Decide(n); got.Blocked || got.Policy != PolicyForwarded {
			t.Errorf("Decide(%q) with filtering off = %+v, want forwarded", n, got)
		}
	}
}

func TestUnmatchedNameIsForwarded(t *testing.T) {
	got := testSnapshot(t, true).Decide("example.org")
	if got.Blocked || got.Policy != PolicyForwarded {
		t.Errorf("Decide(example.org) = %+v, want forwarded", got)
	}
}

// A name that cannot be normalized is forwarded, never blocked. Filtering must
// never be the reason a strange but legal query fails.
func TestUnnormalizableNameIsForwarded(t *testing.T) {
	if got := testSnapshot(t, true).Decide("!!!"); got.Blocked {
		t.Errorf("Decide(!!!) = %+v, want forwarded", got)
	}
}

func TestBlockTTLComesFromSettings(t *testing.T) {
	s := Build(
		store.BlacklistSettings{Enabled: true, BlockTTL: 15},
		[]store.BlacklistList{{Name: "l", Enabled: true, Snapshot: []string{"ads.example"}}},
		nil)
	if got := s.Decide("ads.example"); got.TTL != 15 {
		t.Errorf("TTL = %d, want 15", got.TTL)
	}
}
