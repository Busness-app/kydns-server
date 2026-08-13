package settings

import (
	"testing"
)

func TestBuildParsesEverything(t *testing.T) {
	v := valid()
	v.ReverseZones = []string{"192.168.1.0/24"}
	v.Upstreams = []string{"tls://1.1.1.1:853", "udp://192.168.1.1:53"}

	snap, err := Build(v)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(snap.Upstreams) != 2 {
		t.Fatalf("got %d upstreams, want 2", len(snap.Upstreams))
	}
	// Upstreams are tried in order, so Build must not reorder them.
	if snap.Upstreams[0].String() != "tls://1.1.1.1:853" {
		t.Errorf("upstream order changed: %s", snap.Upstreams[0])
	}
	if len(snap.ReverseZones) != 1 || snap.ReverseZones[0].String() != "192.168.1.0/24" {
		t.Errorf("reverse zones: %v", snap.ReverseZones)
	}
	if len(snap.AllowQuery) != 1 {
		t.Fatalf("allow_query: %v", snap.AllowQuery)
	}
}

// AllowTailscale is a checkbox, not a range the operator types. The snapshot is
// what the ACL reads, so the range has to be in it.
func TestBuildAddsTailscaleRange(t *testing.T) {
	v := valid()
	v.AllowTailscale = true
	snap, err := Build(v)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range snap.AllowQuery {
		if p.String() == "100.64.0.0/10" {
			found = true
		}
	}
	if !found {
		t.Errorf("allow_tailscale on, but CGNAT is not in the ACL: %v", snap.AllowQuery)
	}

	v.AllowTailscale = false
	snap, err = Build(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range snap.AllowQuery {
		if p.String() == "100.64.0.0/10" {
			t.Error("allow_tailscale off, but CGNAT is in the ACL")
		}
	}
}

// Build is the only fallible step of an apply. It must fail before anything is
// swapped, never halfway through.
func TestBuildFailsWholeOnBadUpstream(t *testing.T) {
	v := valid()
	v.Upstreams = []string{"tls://1.1.1.1:853", "tls://example.com:853"}
	if _, err := Build(v); err == nil {
		t.Fatal("Build accepted a hostname upstream; it must fail before any swap")
	}
}

func TestBuildKeepsRaw(t *testing.T) {
	v := valid()
	v.TTL = 120
	snap, err := Build(v)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Raw.TTL != 120 {
		t.Errorf("Raw.TTL is %d, want 120", snap.Raw.TTL)
	}
}
