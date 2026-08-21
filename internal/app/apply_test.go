package app

import (
	"context"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/yoshiofthewire/kydns-server/internal/discovery"
	"github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp"
	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/health"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/settings"
	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/upstream"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)

type fakeLister struct{}

func (fakeLister) Services() ([]store.Service, error) { return nil, nil }

type fakeSource struct{}

func (fakeSource) Leases(context.Context) ([]dhcp.Lease, error) { return nil, nil }
func (fakeSource) Name() string                                 { return "fake" }

// newLiveComponents builds every component the real Serve wires into
// liveComponents, using the same constructors Serve uses. It is deliberately
// not a stripped-down stand-in: this is what proves Apply reaches the real
// implementations, not a mirror of them.
func newLiveComponents(t *testing.T) (*liveComponents, *zone.Holder) {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)

	acl := dnsserver.NewACL(nil)
	cache := dnsserver.NewCache(1000, 1, 3600, 60)
	ups, err := upstream.NewAll([]string{"udp://1.1.1.1:53"}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fwd := dnsserver.NewForwarder(ups, 2*time.Second, cache)
	authoritative := dnsserver.NewAuthoritative("home.arpa.", 300, nil)

	// The snapshot reads the live zone, as Serve's closure reads it from the
	// settings holder: a rename has to reach the snapshot too, not just the
	// answerer's Owns check.
	zoneHolder := zone.NewHolder(func() (zone.Input, error) {
		return zone.Input{Zone: authoritative.Zone()}, nil
	}, logger)
	if err := zoneHolder.Rebuild(); err != nil {
		t.Fatal(err)
	}

	dnsSrv := dnsserver.New(dnsserver.Options{
		Holder: zoneHolder, ACL: acl, Auth: authoritative, Forwarder: fwd,
		LogQueries: false, LogClientIP: false, Logger: logger,
	})

	checker := health.NewChecker(fakeLister{}, 30*time.Second, 5*time.Second, 4, logger)
	poller := discovery.NewPoller(fakeSource{}, 60*time.Second, nil, logger)

	st, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	reg := registry.New(st, "home.arpa.", nil)

	return &liveComponents{
		acl: acl, forwarder: fwd, cache: cache, dnsSrv: dnsSrv,
		authoritative: authoritative, checker: checker, poller: poller,
		zoneHolder: zoneHolder, registry: reg, logger: logger,
		prevUpstreams: []string{"udp://1.1.1.1:53"},
	}, zoneHolder
}

func validSnapshot(t *testing.T) *settings.Snapshot {
	t.Helper()
	v := store.Settings{
		PrivateDomain:     "home.arpa",
		ReverseZones:      []string{"192.168.1.0/24"},
		Upstreams:         []string{"udp://9.9.9.9:53"},
		AllowQuery:        []string{"192.168.0.0/16"},
		TTL:               120,
		CacheMinTTL:       2,
		CacheMaxTTL:       1800,
		NegativeMaxTTL:    30,
		CacheEntries:      3,
		LogQueries:        true,
		LogClientIP:       true,
		DiscoveryInterval: 45,
		HealthInterval:    20,
		HealthTimeout:     4,
		HealthWorkers:     2,
	}
	snap, err := settings.Build(v)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// TestApplyFansOutToEveryLiveComponent is the mandatory carried-over proof
// that the fan-out inside Serve actually works, not merely that it is
// written: it builds the real components Serve builds, calls the real
// Apply method, and checks each of the nine calls plus the zone rebuild
// landed. Deleting any one call from liveComponents.Apply makes the
// corresponding assertion here fail (verified by hand for each, see the
// task report).
func TestApplyFansOutToEveryLiveComponent(t *testing.T) {
	live, zoneHolder := newLiveComponents(t)
	snap := validSnapshot(t)

	genBefore := zoneHolder.Generation()
	// Pre-populate the cache so call 3 (flush on upstream change) is
	// observable: validSnapshot's upstream differs from prevUpstreams.
	live.cache.Put(fakeQuestion(99), false, fakeAnswer())

	live.Apply(snap)

	// 1: ACL replaced.
	inside := netip.MustParseAddr("192.168.1.5")
	outside := netip.MustParseAddr("8.8.8.8")
	if !live.acl.Allow(inside) {
		t.Error("ACL was not replaced: an address in the new allow_query was refused")
	}
	if live.acl.Allow(outside) {
		t.Error("ACL was not replaced: an address outside the new allow_query was allowed")
	}

	// 2: forwarder upstreams replaced.
	statuses := live.forwarder.Status()
	if len(statuses) != 1 || statuses[0].Spec != "udp://9.9.9.9:53" {
		t.Errorf("forwarder was not replaced: %+v", statuses)
	}

	// 3: cache flushed because the upstream list changed.
	if live.cache.Len() != 0 {
		t.Errorf("cache was not flushed on the upstream change: len=%d", live.cache.Len())
	}

	// 4: cache retuned. Fill it past the new, smaller maxEntries (3) so only
	// a real Retune's eviction loop can bring it back under the limit.
	for i := 0; i < 10; i++ {
		live.cache.Put(fakeQuestion(i), false, fakeAnswer())
	}
	if live.cache.Len() > 3 {
		t.Errorf("cache was not retuned to the new maxEntries: len=%d", live.cache.Len())
	}

	// 5: query/client-IP logging flags.
	if !live.dnsSrv.LogQueries() || !live.dnsSrv.LogClientIP() {
		t.Error("dnsSrv logging flags were not applied")
	}

	// 6 & 7: authoritative TTL and reverse zones, checked together through the
	// same public path a real query takes. A PTR question inside the new
	// reverse zone (192.168.1.0/24) only gets an authoritative answer at all
	// if SetReverseZones landed (Owns must return true), and the synthesized
	// SOA in that answer carries the TTL SetTTL applied.
	ptrQ := dns.Question{Name: "5.1.168.192.in-addr.arpa.", Qtype: dns.TypePTR, Qclass: dns.ClassINET}
	m := live.authoritative.Answer(live.zoneHolder.Current(), "", ptrQ)
	if m == nil {
		t.Fatal("authoritative reverse zones were not applied: the new reverse zone is not owned")
	}
	if len(m.Ns) != 1 {
		t.Fatalf("expected a synthesized SOA for an unknown PTR name, got %+v", m)
	}
	if ttl := m.Ns[0].Header().Ttl; ttl != 120 {
		t.Errorf("authoritative TTL = %d, want 120", ttl)
	}

	// 8: health checker reconfigured.
	interval, timeout, workers := live.checker.Config()
	if interval != 20*time.Second || timeout != 4*time.Second || workers != 2 {
		t.Errorf("checker not reconfigured: interval=%s timeout=%s workers=%d", interval, timeout, workers)
	}

	// 9: discovery poller interval.
	if live.poller.Interval() != 45*time.Second {
		t.Errorf("poller interval = %s, want 45s", live.poller.Interval())
	}

	// 10: zone snapshot rebuilt (reverse zones are an input to it).
	if zoneHolder.Generation() == genBefore {
		t.Error("zone snapshot was not rebuilt after the settings change")
	}
}

// TestApplyDoesNotPanicWithDiscoveryOff is the default deployment: DHCP
// discovery off, poller nil. A settings save must not crash the server that
// most installs actually run. This is not a hypothetical: the `if l.poller
// != nil` guard existing but the assignment inside it firing unconditionally
// would compile, pass every other test in this file, and panic on a nil
// receiver the first time anyone saves settings with discovery off.
func TestApplyDoesNotPanicWithDiscoveryOff(t *testing.T) {
	live, _ := newLiveComponents(t)
	live.poller = nil

	live.Apply(validSnapshot(t))
}

// dhcp_lease_file applies live now: the poller always exists and Apply swaps
// its source. This is what replaced the restart banner that used to name it,
// so it has to actually work rather than merely have stopped being announced.
func TestApplySwapsTheLeaseSource(t *testing.T) {
	live, _ := newLiveComponents(t)

	live.Apply(validSnapshot(t)) // no dhcp_lease_file
	if live.poller.Enabled() {
		t.Error("discovery is on with no lease source configured")
	}

	v := validSnapshot(t).Raw
	v.DHCPLeaseFile = "/var/lib/misc/dnsmasq.leases"
	snap, err := settings.Build(v)
	if err != nil {
		t.Fatal(err)
	}
	live.Apply(snap)
	if !live.poller.Enabled() {
		t.Fatal("dhcp_lease_file was set but discovery stayed off, so the operator would have to restart")
	}

	v.DHCPLeaseFile = ""
	snap, err = settings.Build(v)
	if err != nil {
		t.Fatal(err)
	}
	live.Apply(snap)
	if live.poller.Enabled() {
		t.Error("clearing dhcp_lease_file left the old source publishing leases")
	}
}

// TestApplyFlushesCacheOnlyWhenUpstreamsChange guards call 3 specifically:
// an unrelated save must not empty every client's cache.
func TestApplyFlushesCacheOnlyWhenUpstreamsChange(t *testing.T) {
	live, _ := newLiveComponents(t)
	live.cache.Put(fakeQuestion(0), false, fakeAnswer())
	if live.cache.Len() != 1 {
		t.Fatal("setup: cache did not accept the entry")
	}

	v := store.Settings{
		PrivateDomain: "home.arpa", ReverseZones: nil,
		Upstreams:  []string{"udp://1.1.1.1:53"}, // unchanged from prevUpstreams
		AllowQuery: []string{"192.168.0.0/16"}, TTL: 300,
		CacheMinTTL: 1, CacheMaxTTL: 3600, NegativeMaxTTL: 60, CacheEntries: 1000,
		DiscoveryInterval: 60, HealthInterval: 30, HealthTimeout: 5, HealthWorkers: 4,
	}
	snap, err := settings.Build(v)
	if err != nil {
		t.Fatal(err)
	}
	live.Apply(snap)
	if live.cache.Len() != 1 {
		t.Error("an unrelated apply flushed the cache")
	}
}

// fakeQuestion gives each cache.Put a distinct key, so filling the cache
// past the retuned maxEntries actually exercises eviction rather than
// overwriting one entry repeatedly.
func fakeQuestion(i int) dns.Question {
	return dns.Question{
		Name:   dns.Fqdn(string(rune('a'+i)) + ".example.com"),
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}
}

func fakeAnswer() *dns.Msg {
	m := new(dns.Msg)
	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	m.Answer = []dns.RR{rr}
	return m
}

// The private domain is editable at runtime, so a save has to move the whole
// server onto the new zone: the answerer, the registry that validates new
// names, the snapshot that holds them, and the cache full of answers for names
// that no longer exist.
func TestApplyRenamesTheZoneEverywhere(t *testing.T) {
	live, zoneHolder := newLiveComponents(t)

	// A cached answer under the old zone. Nothing else evicts it.
	live.cache.Put(fakeQuestion(1), false, fakeAnswer())

	snap := validSnapshot(t)
	snap.Raw.PrivateDomain = "lan.example"
	live.Apply(snap)

	if got := live.authoritative.Zone(); got != "lan.example." {
		t.Errorf("answerer zone = %q, want lan.example.", got)
	}
	if live.authoritative.Owns("nas.home.arpa.") {
		t.Error("still authoritative for the old zone")
	}
	if !live.authoritative.Owns("nas.lan.example.") {
		t.Error("not authoritative for the new zone")
	}
	if got := live.registry.Zone(); got != "lan.example." {
		t.Errorf("registry zone = %q, want lan.example.: new names would be validated against the old zone", got)
	}
	if got := zoneHolder.Current().Zone; got != "lan.example." {
		t.Errorf("snapshot zone = %q, want lan.example.", got)
	}
	if live.cache.Len() != 0 {
		t.Errorf("cache holds %d entries after the rename; answers for the old zone would keep being served", live.cache.Len())
	}
}

// Every other save must leave the zone alone. Flushing the cache on each
// unrelated settings change would throw away every cached answer for nothing.
func TestApplyLeavesTheZoneAloneWhenTheDomainIsUnchanged(t *testing.T) {
	live, _ := newLiveComponents(t)
	live.cache.Put(fakeQuestion(1), false, fakeAnswer())

	snap := validSnapshot(t) // PrivateDomain is home.arpa, the running zone
	snap.Raw.Upstreams = live.prevUpstreams
	live.Apply(snap)

	if got := live.authoritative.Zone(); got != "home.arpa." {
		t.Errorf("zone = %q, want it unchanged", got)
	}
	if live.cache.Len() == 0 {
		t.Error("cache was flushed by a save that did not touch the zone")
	}
}
