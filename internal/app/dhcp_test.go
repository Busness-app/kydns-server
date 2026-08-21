package app

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/discovery"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// A replica is the exception, not the primary: RoleStandalone is what most
// installs run, and gating on RolePrimary would mean DHCP never starts for
// them. The rule the spec states is "a replica never serves DHCP".
func TestDHCPWantedUnlessReplica(t *testing.T) {
	cases := []struct {
		name    string
		enabled bool
		iface   string
		role    Role
		want    bool
	}{
		{"enabled on a primary", true, "eth0", RolePrimary, true},
		{"enabled on a standalone node", true, "eth0", RoleStandalone, true},
		{"disabled", false, "eth0", RolePrimary, false},
		{"enabled with no interface", true, "", RolePrimary, false},
		{"enabled on a replica", true, "eth0", RoleReplica, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := store.Settings{DHCPEnabled: c.enabled, DHCPInterface: c.iface}
			if got := dhcpWanted(v, c.role); got != c.want {
				t.Fatalf("dhcpWanted(enabled=%v, iface=%q, role=%v) = %v, want %v",
					c.enabled, c.iface, c.role, got, c.want)
			}
		})
	}
}

func TestDHCPConfigEqualCoversEveryBuildInput(t *testing.T) {
	base := store.Settings{
		DHCPEnabled: true, DHCPInterface: "eth0",
		DHCPRangeStart: "192.168.1.100", DHCPRangeEnd: "192.168.1.200",
		DHCPGateway: "192.168.1.1", DHCPLeaseSeconds: 3600,
		DHCPSecondaryDNS: "9.9.9.9", PrivateDomain: "home.arpa",
	}
	if !dhcpConfigEqual(base, base) {
		t.Fatal("a settings value is not equal to itself")
	}
	// Every field build() reads. A field missing here would save without
	// restarting the listener, so the new value would never take effect.
	mutations := map[string]func(*store.Settings){
		"enabled":       func(v *store.Settings) { v.DHCPEnabled = false },
		"interface":     func(v *store.Settings) { v.DHCPInterface = "eth1" },
		"range_start":   func(v *store.Settings) { v.DHCPRangeStart = "192.168.1.101" },
		"range_end":     func(v *store.Settings) { v.DHCPRangeEnd = "192.168.1.201" },
		"gateway":       func(v *store.Settings) { v.DHCPGateway = "192.168.1.254" },
		"lease_seconds": func(v *store.Settings) { v.DHCPLeaseSeconds = 7200 },
		"secondary_dns": func(v *store.Settings) { v.DHCPSecondaryDNS = "1.1.1.1" },
		"domain":        func(v *store.Settings) { v.PrivateDomain = "lan" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			other := base
			mutate(&other)
			if dhcpConfigEqual(base, other) {
				t.Fatalf("a change to %s is not noticed, so it would never be applied", name)
			}
		})
	}
	// Not a build input: changing it must not tear down a working listener.
	other := base
	other.DiscoveryInterval = 120
	if !dhcpConfigEqual(base, other) {
		t.Error("an unrelated setting restarts the listener")
	}
}

// newTestRunner builds a runner with a real poller and no listener. Nothing
// here opens a socket: every path under test refuses before Start.
func newTestRunner(role Role) (*dhcpRunner, *discovery.Poller) {
	p := discovery.NewPoller(nil, time.Hour, nil, slog.New(slog.DiscardHandler))
	return &dhcpRunner{
		poller: p,
		logger: slog.New(slog.DiscardHandler),
		role:   func() Role { return role },
	}, p
}

// A replica must not even try, so nothing it could fail at is reached.
func TestReconcileOnAReplicaNeverStarts(t *testing.T) {
	d, p := newTestRunner(RoleReplica)
	d.Reconcile(store.Settings{
		DHCPEnabled: true, DHCPInterface: "eth0",
		DHCPRangeStart: "192.168.1.100", DHCPRangeEnd: "192.168.1.200",
		DHCPGateway: "192.168.1.1", DHCPLeaseSeconds: 3600,
	})
	running, err := d.Status()
	if running {
		t.Error("a replica started the DHCP listener")
	}
	if err != nil {
		t.Errorf("a replica reported an error rather than simply not serving: %v", err)
	}
	if p.Enabled() {
		t.Error("a replica published a lease source")
	}
}

// A build that refuses is reported, not swallowed: the UI shows lastError
// when DHCP is configured and not running.
func TestReconcileReportsWhyItCannotStart(t *testing.T) {
	d, p := newTestRunner(RoleStandalone)
	d.Reconcile(store.Settings{
		// No such interface, so Qualifies refuses before any socket is opened.
		DHCPEnabled: true, DHCPInterface: "kydns-no-such-iface0",
		DHCPRangeStart: "192.168.1.100", DHCPRangeEnd: "192.168.1.200",
		DHCPGateway: "192.168.1.1", DHCPLeaseSeconds: 3600,
	})
	running, err := d.Status()
	if running {
		t.Fatal("Status reports a listener that was never started")
	}
	if err == nil {
		t.Fatal("a refused start reported no reason")
	}
	if !strings.Contains(err.Error(), "kydns-no-such-iface0") {
		t.Errorf("the reason does not name the interface: %v", err)
	}
	if p.Enabled() {
		t.Error("a failed start published a lease source")
	}

	// Turning DHCP off clears the error rather than leaving the UI accusing
	// the operator of a setting they have already removed.
	d.Reconcile(store.Settings{})
	if _, err := d.Status(); err != nil {
		t.Errorf("disabling DHCP left the old error behind: %v", err)
	}
}

func TestParseSettingNamesTheField(t *testing.T) {
	if _, err := parseSetting("dhcp.gateway", "not-an-ip"); err == nil {
		t.Fatal("a malformed address parsed")
	} else if !strings.Contains(err.Error(), "dhcp.gateway") {
		t.Errorf("the error does not name the setting: %v", err)
	}
	if a, err := parseSetting("dhcp.gateway", "192.168.1.1"); err != nil || a.String() != "192.168.1.1" {
		t.Errorf("parseSetting(valid) = %v, %v", a, err)
	}
}

// Promotion starts the listener. A replica is promoted precisely when the
// primary it was following has gone, which is when the LAN has no DHCP server:
// waiting for the next settings save or restart is the wrong moment to wait.
func TestPromotionReconcilesDHCP(t *testing.T) {
	roleHolder := NewRoleHolder(RoleReplica)
	p := discovery.NewPoller(nil, time.Hour, nil, slog.New(slog.DiscardHandler))
	d := &dhcpRunner{
		poller: p,
		logger: slog.New(slog.DiscardHandler),
		role:   roleHolder.Current,
	}
	// No such interface, so the reconcile refuses at Qualifies before any
	// socket is opened. That refusal is the observable proof it ran at all: a
	// replica never reaches build, so it cannot produce an error.
	v := store.Settings{
		DHCPEnabled: true, DHCPInterface: "kydns-no-such-iface0",
		DHCPRangeStart: "192.168.1.100", DHCPRangeEnd: "192.168.1.200",
		DHCPGateway: "192.168.1.1", DHCPLeaseSeconds: 3600,
	}
	d.Reconcile(v)
	if running, err := d.Status(); running || err != nil {
		t.Fatalf("as a replica: running=%v, err=%v; want not running and no error", running, err)
	}

	promoter := &replicaPromoter{
		st:        openDB(t, t.TempDir()),
		role:      roleHolder,
		onPromote: func() { d.Reconcile(v) },
	}
	changed, err := promoter.Promote()
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if !changed {
		t.Fatal("Promote reported no change on a replica")
	}
	running, err := d.Status()
	if running {
		t.Fatal("the listener bound in a test, which should be impossible here")
	}
	if err == nil {
		t.Fatal("promotion did not reconcile DHCP: the runner never attempted a start")
	}
	if !strings.Contains(err.Error(), "kydns-no-such-iface0") {
		t.Errorf("the attempt was not the one this settings value asks for: %v", err)
	}
}

// The tests above build promoters directly, and so does anything else that
// does not care about DHCP. A missing hook must not take promotion down.
func TestPromoteWithoutAnOnPromoteHook(t *testing.T) {
	p := &replicaPromoter{st: openDB(t, t.TempDir()), role: NewRoleHolder(RoleReplica)}
	if changed, err := p.Promote(); err != nil || !changed {
		t.Fatalf("Promote with a nil onPromote = %v, %v", changed, err)
	}
}
