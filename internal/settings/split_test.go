package settings

import (
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func TestMergeReplicatedTakesSharedKeys(t *testing.T) {
	local := store.Settings{PrivateDomain: "old.arpa", TTL: 60,
		Upstreams: []string{"tls://1.1.1.1:853"}}
	incoming := store.Settings{PrivateDomain: "home.arpa", TTL: 120,
		Upstreams: []string{"tls://9.9.9.9:853"}}

	got := MergeReplicated(local, incoming)

	if got.PrivateDomain != "home.arpa" {
		t.Errorf("PrivateDomain = %q, want home.arpa", got.PrivateDomain)
	}
	if got.TTL != 120 {
		t.Errorf("TTL = %d, want 120", got.TTL)
	}
	if len(got.Upstreams) != 1 || got.Upstreams[0] != "tls://9.9.9.9:853" {
		t.Errorf("Upstreams = %v, want [tls://9.9.9.9:853]", got.Upstreams)
	}
}

// The whole point of the split: a primary must never reach into a replica's
// lease file path or its query-logging privacy choice.
func TestMergeReplicatedKeepsNodeLocalKeys(t *testing.T) {
	local := store.Settings{
		DHCPLeaseFile: "/var/lib/misc/dnsmasq.leases", DiscoveryInterval: 15,
		LogQueries: true, LogClientIP: true,
	}
	incoming := store.Settings{
		DHCPLeaseFile: "/somewhere/on/the/primary", DiscoveryInterval: 300,
		LogQueries: false, LogClientIP: false,
	}

	got := MergeReplicated(local, incoming)

	if got.DHCPLeaseFile != "/var/lib/misc/dnsmasq.leases" {
		t.Errorf("DHCPLeaseFile = %q, want the local path", got.DHCPLeaseFile)
	}
	if got.DiscoveryInterval != 15 {
		t.Errorf("DiscoveryInterval = %d, want 15", got.DiscoveryInterval)
	}
	if !got.LogQueries {
		t.Error("LogQueries = false, want the local true")
	}
	if !got.LogClientIP {
		t.Error("LogClientIP = false, want the local true")
	}
}

// Slices must be copied, not aliased: a merged result that shares backing
// memory with the incoming document mutates when the document is reused.
func TestMergeReplicatedCopiesSlices(t *testing.T) {
	incoming := store.Settings{Upstreams: []string{"tls://1.1.1.1:853"}}
	got := MergeReplicated(store.Settings{}, incoming)
	incoming.Upstreams[0] = "udp://192.168.1.1:53"
	if got.Upstreams[0] != "tls://1.1.1.1:853" {
		t.Fatalf("Upstreams[0] = %q, want the value at merge time", got.Upstreams[0])
	}
}
