package app

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/Busness-app/kydns-server/internal/dhcpd"
	"github.com/Busness-app/kydns-server/internal/discovery"
	"github.com/Busness-app/kydns-server/internal/settings"
	"github.com/Busness-app/kydns-server/internal/store"
)

// replicaDHCPRig wires the three pieces the exemption spans as serve.go does:
// a settings service that reads the role per write, a role holder, and the
// runner the service applies onto. Nothing here can open a socket - start is
// injected and only records that a bind was attempted.
type replicaDHCPRig struct {
	svc   *settings.Service
	role  *RoleHolder
	run   *dhcpRunner
	binds *int
}

func newReplicaDHCPRig(t *testing.T) replicaDHCPRig {
	t.Helper()
	st := openDB(t, t.TempDir())
	base := store.Settings{
		PrivateDomain: "home.arpa",
		Upstreams:     []string{"udp://1.1.1.1:53"},
		AllowQuery:    []string{"192.168.0.0/16"},
		TTL:           300, CacheMinTTL: 1, CacheMaxTTL: 3600,
		NegativeMaxTTL: 60, CacheEntries: 1000,
		DiscoveryInterval: 60, HealthInterval: 30, HealthTimeout: 5, HealthWorkers: 4,
	}
	if err := st.PutSettings(base); err != nil {
		t.Fatal(err)
	}
	h := settings.NewHolder(func() (store.Settings, error) {
		v, _, err := st.Settings()
		return v, err
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}

	role := NewRoleHolder(RoleReplica)
	p := discovery.NewPoller(nil, time.Hour, nil, slog.New(slog.DiscardHandler))
	binds := 0
	run := &dhcpRunner{
		poller:   p,
		logger:   slog.New(slog.DiscardHandler),
		role:     role.Current,
		services: func() ([]store.Service, error) { return nil, nil },
		// Host state all succeeds, so the only thing left to stop a replica is
		// the role itself.
		qualifies:     func(string) error { return nil },
		inspect:       fakeIface,
		detectForeign: func(context.Context, string, time.Duration) ([]dhcpd.Foreign, error) { return nil, nil },
		start:         func(built) error { binds++; return nil },
	}
	svc := settings.NewService(st, h, func(snap *settings.Snapshot) { run.Reconcile(snap.Raw) },
		func() bool { return role.Current() == RoleReplica })
	t.Cleanup(func() { run.Reconcile(store.Settings{}) })
	return replicaDHCPRig{svc: svc, role: role, run: run, binds: &binds}
}

// dhcpConfigured is the running row with the built-in server switched on.
func dhcpConfigured(t *testing.T, svc *settings.Service) store.Settings {
	t.Helper()
	v, err := svc.Get()
	if err != nil {
		t.Fatal(err)
	}
	v.DHCPEnabled, v.DHCPInterface = true, "eth0"
	v.DHCPRangeStart, v.DHCPRangeEnd = "192.168.1.100", "192.168.1.200"
	v.DHCPGateway, v.DHCPLeaseSeconds = "192.168.1.1", 3600
	return v
}

// The whole shape of this task in one test: a replica may configure DHCP, it
// still must not serve it, and promotion starts it without a restart.
func TestAReplicaConfiguresDHCPWithoutServingItAndPromotionStartsIt(t *testing.T) {
	r := newReplicaDHCPRig(t)

	if err := r.svc.Set(dhcpConfigured(t, r.svc), ""); err != nil {
		t.Fatalf("a replica could not save its DHCP settings: %v", err)
	}
	stored, err := r.svc.Get()
	if err != nil {
		t.Fatal(err)
	}
	if !stored.DHCPEnabled || stored.DHCPInterface != "eth0" {
		t.Fatalf("the save did not stick: %+v", stored)
	}

	running, reason := r.run.Status()
	if running || *r.binds != 0 {
		t.Fatalf("a replica bound the DHCP listener: running=%v binds=%d", running, *r.binds)
	}
	if reason == nil || reason.Error() != errReplicaNoDHCP.Error() {
		t.Fatalf("a configured replica reports %v, want the role refusal", reason)
	}

	// Promotion, with nothing else touched: no restart, no second save.
	r.role.Set(RolePrimary)
	r.run.Reconcile(stored)
	if running, err := r.run.Status(); !running || err != nil {
		t.Fatalf("after promotion: running=%v err=%v; want the listener started", running, err)
	}
	if *r.binds != 1 {
		t.Fatalf("binds = %d, want exactly one after promotion", *r.binds)
	}
}

// The exemption is scoped at the settings service, so it holds for whatever
// calls it - not only for the two routes the gates let through.
func TestAReplicaCannotChangeANonDHCPSettingThroughTheSameService(t *testing.T) {
	r := newReplicaDHCPRig(t)
	v := dhcpConfigured(t, r.svc)
	v.Upstreams = []string{"udp://9.9.9.9:53"}
	if err := r.svc.Set(v, ""); err == nil {
		t.Fatal("a replica changed an upstream through the DHCP write path")
	}
	got, err := r.svc.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.Upstreams[0] != "udp://1.1.1.1:53" {
		t.Errorf("upstreams = %v, want the primary's", got.Upstreams)
	}
	if got.DHCPEnabled {
		t.Error("the DHCP half of a refused mixed write was applied")
	}
}
