package app

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/dhcpd"
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

// A replica must not even try, so nothing it could fail at is reached. It says
// so, though: DHCP configured and not running with no reason at all reads as
// broken rather than as correct.
func TestReconcileOnAReplicaNeverStartsAndSaysWhy(t *testing.T) {
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
	if !errors.Is(err, errReplicaNoDHCP) {
		t.Errorf("a replica reported %v, want the role refusal", err)
	}
	if p.Enabled() {
		t.Error("a replica published a lease source")
	}

	// Not configured for DHCP at all: nothing to explain.
	d.Reconcile(store.Settings{})
	if _, err := d.Status(); err != nil {
		t.Errorf("a node with DHCP off reported %v, want no reason at all", err)
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
	// The validator trims before parsing, so " 192.168.1.100" saves green.
	// Not trimming here would make it save and then never start.
	if a, err := parseSetting("dhcp.range_start", " 192.168.1.100\t"); err != nil || a.String() != "192.168.1.100" {
		t.Errorf("parseSetting(padded) = %v, %v; the validator accepts what this refuses", a, err)
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
	if running, err := d.Status(); running || !errors.Is(err, errReplicaNoDHCP) {
		t.Fatalf("as a replica: running=%v, err=%v; want not running, with the role as the reason", running, err)
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

// fakeIface is the host state build reads. Injected, so no test in this file
// needs a real interface, a raw socket, or a bind.
func fakeIface(name string) (dhcpd.IfaceInfo, error) {
	return dhcpd.IfaceInfo{
		Name:   name,
		Addr:   netip.MustParseAddr("192.168.1.5"),
		Subnet: netip.MustParsePrefix("192.168.1.0/24"),
	}, nil
}

func buildableSettings() store.Settings {
	return store.Settings{
		DHCPEnabled: true, DHCPInterface: "eth0",
		DHCPRangeStart: "192.168.1.100", DHCPRangeEnd: "192.168.1.200",
		DHCPGateway: "192.168.1.1", DHCPLeaseSeconds: 3600,
	}
}

// newBuildableRunner is a runner whose host-state calls all succeed, so a test
// reaches the decisions build makes rather than stopping at Qualifies.
func newBuildableRunner(detect func(context.Context, string, time.Duration) ([]dhcpd.Foreign, error)) (*dhcpRunner, *discovery.Poller) {
	d, p := newTestRunner(RoleStandalone)
	d.qualifies = func(string) error { return nil }
	d.inspect = fakeIface
	d.detectForeign = detect
	return d, p
}

// The rogue check is the whole reason this feature can be turned on safely,
// and a server sharing this host answers with our own address. Refusing has to
// hold for that server too.
func TestBuildRefusesWhenAnotherServerAnswers(t *testing.T) {
	ours := netip.MustParseAddr("192.168.1.5")
	d, _ := newBuildableRunner(func(context.Context, string, time.Duration) ([]dhcpd.Foreign, error) {
		return []dhcpd.Foreign{{ServerID: ours, Offered: netip.MustParseAddr("192.168.1.64")}}, nil
	})
	srv, err := d.build(buildableSettings(), true)
	if err == nil {
		t.Fatalf("build returned %v with another DHCP server answering on the segment", srv)
	}
	var fe *ForeignServerError
	if !errors.As(err, &fe) {
		t.Fatalf("error = %v, want a ForeignServerError", err)
	}
	if !strings.Contains(err.Error(), ours.String()) {
		t.Errorf("the refusal does not name the other server: %v", err)
	}
}

// R22: a probe that could not run is not a clear segment. Guessing "no" would
// drop the protection on exactly the hosts where the probe is hardest to run.
func TestBuildRefusesWhenTheProbeCannotRun(t *testing.T) {
	d, _ := newBuildableRunner(func(context.Context, string, time.Duration) ([]dhcpd.Foreign, error) {
		return nil, errors.New("probe socket: permission denied")
	})
	srv, err := d.build(buildableSettings(), true)
	if err == nil {
		t.Fatalf("build returned %v after a probe that could not run", srv)
	}
	if !strings.Contains(err.Error(), "permission denied") || !strings.Contains(err.Error(), "eth0") {
		t.Errorf("the refusal names neither the cause nor the interface: %v", err)
	}
}

func TestBuildSkipsTheProbeWhenAListenerIsAlreadyBound(t *testing.T) {
	d, _ := newBuildableRunner(func(context.Context, string, time.Duration) ([]dhcpd.Foreign, error) {
		t.Fatal("the probe ran while our own listener held the interface")
		return nil, nil
	})
	if _, err := d.build(buildableSettings(), false); err != nil {
		t.Fatalf("build: %v", err)
	}
}

func TestBuildRefusesAMalformedSecondaryDNS(t *testing.T) {
	d, _ := newBuildableRunner(func(context.Context, string, time.Duration) ([]dhcpd.Foreign, error) {
		return nil, nil
	})
	v := buildableSettings()
	v.DHCPSecondaryDNS = "9.9.9"
	srv, err := d.build(v, true)
	if err == nil {
		t.Fatalf("build returned %v with a malformed secondary DNS, silently dropping it", srv)
	}
	if !strings.Contains(err.Error(), "secondary_dns") {
		t.Errorf("the error does not name the setting: %v", err)
	}
}

func TestNeedsProbe(t *testing.T) {
	v := buildableSettings()
	d, _ := newTestRunner(RoleStandalone)
	if !d.needsProbe(v) {
		t.Error("no listener is running, so the segment has to be checked")
	}
	d.running = dhcpd.New(dhcpd.Options{})
	d.current = v
	if d.needsProbe(v) {
		t.Error("our own listener holds this interface; probing again can only hear nothing")
	}
	other := v
	other.DHCPInterface = "eth1"
	if !d.needsProbe(other) {
		t.Error("a different interface is a segment we have never checked")
	}
}

// I4: Reconcile has three triggers — boot, a settings save, and promotion — so
// a stop that is not followed by a start leaves the LAN with no DHCP server
// and nothing to retry it.
func TestARefusedBuildLeavesTheRunningListenerAlone(t *testing.T) {
	d, p := newBuildableRunner(func(context.Context, string, time.Duration) ([]dhcpd.Foreign, error) {
		return nil, errors.New("probe socket: permission denied")
	})
	// A listener that is up and serving the LAN, published to the poller.
	d.running = dhcpd.New(dhcpd.Options{})
	d.current = buildableSettings()
	d.poller.SetSource(d.running)

	// A new interface, so the probe runs, and it fails.
	v := d.current
	v.DHCPInterface = "eth1"
	d.Reconcile(v)

	running, err := d.Status()
	if !running {
		t.Fatal("a build that refused took the working listener down, with nothing to bring it back")
	}
	if err == nil {
		t.Error("the refusal was not reported")
	}
	if !p.Enabled() {
		t.Error("the lease source was withdrawn from DNS by a build that never replaced it")
	}
	if d.current.DHCPInterface != "eth0" {
		t.Errorf("current names %q, but the listener that is running is on eth0", d.current.DHCPInterface)
	}
}

// fail() leaves current naming the listener that is still up, which is right.
// Re-saving the configuration that listener runs then takes the unchanged-
// config early return, and an operator who has undone their mistake would keep
// reading "running yes" beside a last error that no longer applies.
func TestReSavingTheWorkingConfigClearsTheStaleError(t *testing.T) {
	d, _ := newBuildableRunner(func(context.Context, string, time.Duration) ([]dhcpd.Foreign, error) {
		return nil, errors.New("probe socket: permission denied")
	})
	working := buildableSettings()
	d.running = dhcpd.New(dhcpd.Options{})
	d.current = working
	d.poller.SetSource(d.running)

	// A new interface, so the probe runs, and it fails.
	refused := working
	refused.DHCPInterface = "eth1"
	d.Reconcile(refused)
	if _, err := d.Status(); err == nil {
		t.Fatal("the refused save reported no reason")
	}

	d.Reconcile(working)
	running, err := d.Status()
	if !running {
		t.Fatal("re-saving the working configuration took the listener down")
	}
	if err != nil {
		t.Fatalf("Status reports %v beside a listener that is running the configuration just saved", err)
	}
}
