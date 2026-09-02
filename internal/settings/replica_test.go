package settings

import (
	"errors"
	"reflect"
	"testing"

	"github.com/Busness-app/kydns-server/internal/store"
)

// dhcpOn is valid() with the built-in DHCP server configured.
func dhcpOn(v store.Settings) store.Settings {
	v.DHCPEnabled, v.DHCPInterface = true, "eth0"
	v.DHCPRangeStart, v.DHCPRangeEnd = "192.168.1.100", "192.168.1.200"
	v.DHCPGateway, v.DHCPLeaseSeconds = "192.168.1.1", 3600
	return v
}

// newReplicaService is newTestService with the node reporting itself a
// replica. The flag is a pointer so a test can promote mid-test, the way the
// role holder does.
func newReplicaService(t *testing.T) (*fakeWriter, *Service, *bool) {
	t.Helper()
	w := &fakeWriter{cur: valid()}
	h := NewHolder(func() (store.Settings, error) { return w.cur, nil })
	if err := h.Rebuild(); err != nil {
		t.Fatalf("initial rebuild: %v", err)
	}
	replica := true
	return w, NewService(w, h, nil, func() bool { return replica }), &replica
}

// The default has to point the safe way. This is the one chokepoint the whole
// DHCP exemption rests on, and a call site that forgets the argument is a
// silent hole if nil reads as "primary" — so it reads as "replica", and the
// forgetful caller gets a refusal on its first non-DHCP write instead.
func TestAServiceWiredWithNoRoleRefusesANonDHCPWrite(t *testing.T) {
	w := &fakeWriter{cur: valid()}
	h := NewHolder(func() (store.Settings, error) { return w.cur, nil })
	if err := h.Rebuild(); err != nil {
		t.Fatalf("initial rebuild: %v", err)
	}
	svc := NewService(w, h, nil, nil)

	v := valid()
	v.TTL = 120
	if err := svc.Set(v, ""); !errors.Is(err, ErrReadOnlyReplica) {
		t.Fatalf("a service wired with no role took a ttl write: %v", err)
	}
	if w.writes != 0 {
		t.Errorf("a service wired with no role wrote %d times", w.writes)
	}
}

// The whole point of the exemption: an operator can prepare a standby.
func TestReplicaMaySaveTheDHCPSettings(t *testing.T) {
	w, svc, _ := newReplicaService(t)
	if err := svc.Set(dhcpOn(valid()), ""); err != nil {
		t.Fatalf("a replica could not save its DHCP settings: %v", err)
	}
	if !w.cur.DHCPEnabled || w.cur.DHCPInterface != "eth0" {
		t.Errorf("the DHCP settings did not reach the store: %+v", w.cur)
	}
	if got, err := svc.Get(); err != nil || !got.DHCPEnabled {
		t.Errorf("the running snapshot did not pick the save up: %+v, %v", got, err)
	}
}

// The defect this task must not introduce: exempting the route without
// scoping the write would let a replica change anything the same route reaches.
func TestReplicaRefusesAMixedWriteWhole(t *testing.T) {
	w, svc, _ := newReplicaService(t)
	v := dhcpOn(valid())
	v.TTL = 999
	err := svc.Set(v, "")
	if !errors.Is(err, ErrReadOnlyReplica) {
		t.Fatalf("a mixed write returned %v, want ErrReadOnlyReplica", err)
	}
	// Refused whole, not applied in part: the DHCP half must not land either.
	if w.writes != 0 {
		t.Errorf("a refused write still wrote %d times", w.writes)
	}
	if w.cur.DHCPEnabled {
		t.Error("the DHCP half of a refused mixed write was applied")
	}
	if w.cur.TTL != valid().TTL {
		t.Errorf("ttl = %d, want %d: a replica changed a replicated setting", w.cur.TTL, valid().TTL)
	}
}

// Every non-DHCP field, one at a time, so a field nobody thought about is not
// quietly writable on a replica.
func TestReplicaRefusesEveryNonDHCPField(t *testing.T) {
	cases := map[string]func(*store.Settings){
		"private_domain":     func(v *store.Settings) { v.PrivateDomain = "lan.example" },
		"reverse_zones":      func(v *store.Settings) { v.ReverseZones = []string{"10.0.0.0/8"} },
		"upstreams":          func(v *store.Settings) { v.Upstreams = []string{"tls://9.9.9.9:853"} },
		"allow_query":        func(v *store.Settings) { v.AllowQuery = []string{"10.0.0.0/8"} },
		"allow_tailscale":    func(v *store.Settings) { v.AllowTailscale = true },
		"ttl":                func(v *store.Settings) { v.TTL = 120 },
		"cache_min_ttl":      func(v *store.Settings) { v.CacheMinTTL = 10 },
		"cache_max_ttl":      func(v *store.Settings) { v.CacheMaxTTL = 7200 },
		"negative_max_ttl":   func(v *store.Settings) { v.NegativeMaxTTL = 60 },
		"cache_entries":      func(v *store.Settings) { v.CacheEntries = 20000 },
		"log_queries":        func(v *store.Settings) { v.LogQueries = true },
		"log_client_ip":      func(v *store.Settings) { v.LogClientIP = true },
		"dhcp_lease_file":    func(v *store.Settings) { v.DHCPLeaseFile = "/var/lib/misc/dnsmasq.leases" },
		"discovery_interval": func(v *store.Settings) { v.DiscoveryInterval = 60 },
		"health_interval":    func(v *store.Settings) { v.HealthInterval = 60 },
		"health_timeout":     func(v *store.Settings) { v.HealthTimeout = 10 },
		"health_workers":     func(v *store.Settings) { v.HealthWorkers = 16 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w, svc, _ := newReplicaService(t)
			v := valid()
			mutate(&v)
			if err := svc.Set(v, ""); !errors.Is(err, ErrReadOnlyReplica) {
				t.Fatalf("changing %s on a replica returned %v, want ErrReadOnlyReplica", name, err)
			}
			if w.writes != 0 {
				t.Errorf("changing %s on a replica still wrote", name)
			}
		})
	}
}

// Ruling P22a. The race a replica has and an admin does not: the pull loop
// runs continuously, so the row the caller read may already be stale by the
// time the write lands. A whole-row write would put the caller's stale
// non-DHCP half back and nothing would surface it.
func TestAPullBetweenTheReadAndTheWriteIsNotReverted(t *testing.T) {
	w, svc, _ := newReplicaService(t)

	// What the DHCP form read before the operator pressed Save.
	cur, err := svc.Get()
	if err != nil {
		t.Fatal(err)
	}

	// The pull lands: the stored row moves, and the holder has not caught up
	// yet. That gap is the whole window, and it is not closeable from here.
	pulled := w.cur
	pulled.Upstreams = []string{"tls://9.9.9.9:853"}
	pulled.TTL = 900
	w.cur = pulled

	if err := svc.Set(dhcpOn(cur), ""); err != nil {
		t.Fatalf("the save was refused: %v", err)
	}
	if got := w.cur.Upstreams; len(got) != 1 || got[0] != "tls://9.9.9.9:853" {
		t.Errorf("upstreams = %v, want the pulled value: the save reverted the primary's configuration", got)
	}
	if w.cur.TTL != 900 {
		t.Errorf("ttl = %d, want 900: the save reverted the primary's configuration", w.cur.TTL)
	}
	if !w.cur.DHCPEnabled {
		t.Error("the DHCP half of the save was lost")
	}
	// And the running snapshot converges on the store rather than on v: a
	// snapshot published from the caller's copy would leave the process serving
	// the configuration the pull just replaced.
	got, err := svc.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.TTL != 900 || got.Upstreams[0] != "tls://9.9.9.9:853" {
		t.Errorf("the published snapshot is the caller's stale copy: %+v", got)
	}
}

// Only the eight columns move, so nothing outside them can be written by this
// path even in principle.
func TestTheReplicaWriteTouchesOnlyTheDHCPColumns(t *testing.T) {
	w, svc, _ := newReplicaService(t)
	before := w.cur
	if err := svc.Set(dhcpOn(valid()), ""); err != nil {
		t.Fatal(err)
	}
	if w.narrowWrites != 1 || w.writes != 0 {
		t.Errorf("writes=%d narrow=%d, want the narrow path only", w.writes, w.narrowWrites)
	}
	after := w.cur
	if !after.DHCPEnabled || after.DHCPInterface != "eth0" {
		t.Fatalf("the DHCP half did not land, so there is nothing to bound: %+v", after)
	}
	// Compared whole against the row before the write, with the eight taken
	// from what landed, so a settings field added later is covered. Not through
	// dhcpOnlyChange: that is the function the write path decides with, and a
	// mutant that bypasses it would agree with itself here.
	want := before
	want.DHCPEnabled, want.DHCPInterface = after.DHCPEnabled, after.DHCPInterface
	want.DHCPRangeStart, want.DHCPRangeEnd = after.DHCPRangeStart, after.DHCPRangeEnd
	want.DHCPGateway, want.DHCPLeaseSeconds = after.DHCPGateway, after.DHCPLeaseSeconds
	want.DHCPSecondaryDNS, want.DHCPAllowForeign = after.DHCPSecondaryDNS, after.DHCPAllowForeign
	if !reflect.DeepEqual(after, want) {
		t.Errorf("the narrow write moved something else:\nafter %+v\nwant  %+v", after, want)
	}
}

// A replica's DHCP settings are still validated: the exemption is about who
// may write, not about what is acceptable.
func TestTheReplicaWriteIsStillValidated(t *testing.T) {
	w, svc, _ := newReplicaService(t)
	v := dhcpOn(valid())
	v.DHCPLeaseSeconds = 5 // below the floor
	var fe FieldError
	if err := svc.Set(v, ""); !errors.As(err, &fe) || fe.Field != "dhcp_lease_seconds" {
		t.Fatalf("an invalid lease time on a replica returned %v, want a dhcp_lease_seconds error", err)
	}
	if w.narrowWrites != 0 {
		t.Error("an invalid save still wrote")
	}
}

// Read per write, so promotion widens what is writable without a restart.
func TestPromotionRestoresTheWholeRowWrite(t *testing.T) {
	w, svc, replica := newReplicaService(t)
	v := valid()
	v.TTL = 120
	if err := svc.Set(v, ""); !errors.Is(err, ErrReadOnlyReplica) {
		t.Fatalf("as a replica: %v, want ErrReadOnlyReplica", err)
	}
	*replica = false
	if err := svc.Set(v, ""); err != nil {
		t.Fatalf("after promotion: %v", err)
	}
	if w.cur.TTL != 120 || w.writes != 1 {
		t.Errorf("a promoted node did not take the whole-row write: ttl=%d writes=%d", w.cur.TTL, w.writes)
	}
}

// Nothing changes for a node that is not a replica.
func TestANonReplicaTakesTheWholeRowWrite(t *testing.T) {
	w, svc, _ := newTestService(t)
	v := dhcpOn(valid())
	v.TTL = 120
	if err := svc.Set(v, ""); err != nil {
		t.Fatal(err)
	}
	if w.narrowWrites != 0 {
		t.Error("a standalone node took the replica write path")
	}
	if w.cur.TTL != 120 || !w.cur.DHCPEnabled {
		t.Errorf("the whole-row write did not land: %+v", w.cur)
	}
}
