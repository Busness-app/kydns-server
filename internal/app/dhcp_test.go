package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"reflect"
	"strings"
	"sync"
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
	// build reads this one, but it gates the start rather than shaping the
	// listener: flipping it must not restart a server that is already serving.
	// A refused start retries regardless, because nothing is running to skip.
	other = base
	other.DHCPAllowForeign = true
	if !dhcpConfigEqual(base, other) {
		t.Error("the foreign-server override restarts a listener it cannot change")
	}
}

// newTestRunner builds a runner with a real poller and no listener. Nothing
// here opens a socket: every path under test refuses before Start.
func newTestRunner(role Role) (*dhcpRunner, *discovery.Poller) {
	p := discovery.NewPoller(nil, time.Hour, nil, slog.New(slog.DiscardHandler))
	return &dhcpRunner{
		poller:   p,
		logger:   slog.New(slog.DiscardHandler),
		role:     func() Role { return role },
		services: func() ([]store.Service, error) { return nil, nil },
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
		poller:   p,
		logger:   slog.New(slog.DiscardHandler),
		role:     roleHolder.Current,
		services: func() ([]store.Service, error) { return nil, nil },
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

func TestForeignServerErrorNamesTheOtherServer(t *testing.T) {
	err := &ForeignServerError{Found: []dhcpd.Foreign{{
		ServerID: netip.MustParseAddr("192.168.1.1"),
		Offered:  netip.MustParseAddr("192.168.1.64"),
	}}}
	msg := err.Error()
	if !strings.Contains(msg, "192.168.1.1") {
		t.Fatalf("error %q does not name the other server; an operator cannot act on it", msg)
	}
	if !strings.Contains(msg, "192.168.1.64") {
		t.Fatalf("error %q does not say what was offered", msg)
	}
}

func TestForeignServerIsFatalUnlessOverridden(t *testing.T) {
	found := []dhcpd.Foreign{{
		ServerID: netip.MustParseAddr("192.168.1.1"),
		Offered:  netip.MustParseAddr("192.168.1.64"),
	}}
	if err := foreignVerdict(found, nil, false); err == nil {
		t.Fatal("a foreign DHCP server was accepted without an override")
	}
	if err := foreignVerdict(found, nil, true); err != nil {
		t.Fatalf("the override did not take: %v", err)
	}
	if err := foreignVerdict(nil, nil, false); err != nil {
		t.Fatalf("a clear probe was treated as a failure: %v", err)
	}
	if err := foreignVerdict(nil, errors.New("probe socket: address in use"), false); err == nil {
		t.Fatal("a probe that could not run was treated as a clear")
	}
	if err := foreignVerdict(nil, errors.New("probe socket: address in use"), true); err != nil {
		t.Fatalf("the override did not cover a probe that could not run: %v", err)
	}
}

// The override is what an operator whose own DHCP client holds :68 has to
// reach for, so it has to survive the whole build path, not just the verdict.
func TestBuildStartsWithTheOverrideOn(t *testing.T) {
	d, _ := newBuildableRunner(func(context.Context, string, time.Duration) ([]dhcpd.Foreign, error) {
		return []dhcpd.Foreign{{
			ServerID: netip.MustParseAddr("192.168.1.1"),
			Offered:  netip.MustParseAddr("192.168.1.64"),
		}}, errors.New("probe socket: address in use")
	})
	v := buildableSettings()
	v.DHCPAllowForeign = true
	if _, err := d.build(v, true); err != nil {
		t.Fatalf("build refused with the override on: %v", err)
	}
}

// The periodic probe warns and populates the banner. It never stops the
// listener: pulling DHCP out from under a working network over one transient
// answer is worse than the conflict it reacts to.
func TestThePeriodicProbeWarnsAndLeavesTheListenerUp(t *testing.T) {
	d, p := newTestRunner(RoleStandalone)
	d.running = dhcpd.New(dhcpd.Options{})
	d.current = buildableSettings()
	d.poller.SetSource(d.running)

	found := []dhcpd.Foreign{{
		ServerID: netip.MustParseAddr("192.168.1.1"),
		Offered:  netip.MustParseAddr("192.168.1.64"),
	}}
	d.checkForeign(context.Background(), func(context.Context, time.Duration) ([]dhcpd.Foreign, error) {
		return found, nil
	})

	running, err := d.Status()
	if !running {
		t.Fatal("the periodic probe took a working listener down")
	}
	if err != nil {
		t.Errorf("the periodic probe reported %v as a start failure", err)
	}
	if !p.Enabled() {
		t.Error("the periodic probe withdrew the lease source from DNS")
	}
	if got := d.Foreign(); len(got) != 1 || got[0].ServerID != found[0].ServerID {
		t.Fatalf("Foreign() = %+v, want the other server for the banner", got)
	}
}

// R22 again: a probe that could not run is not a clear segment, so it must
// not blank a banner that is reporting a real conflict.
func TestAFailedPeriodicProbeIsNotReportedAsClear(t *testing.T) {
	d, _ := newTestRunner(RoleStandalone)
	found := []dhcpd.Foreign{{ServerID: netip.MustParseAddr("192.168.1.1")}}
	d.checkForeign(context.Background(), func(context.Context, time.Duration) ([]dhcpd.Foreign, error) {
		return found, nil
	})
	d.checkForeign(context.Background(), func(context.Context, time.Duration) ([]dhcpd.Foreign, error) {
		return nil, errors.New("probe socket: address in use")
	})
	if got := d.Foreign(); len(got) != 1 {
		t.Fatalf("Foreign() = %+v after a probe that could not run, want the last known conflict kept", got)
	}
}

// Foreign() feeds a JSON payload the API builds without the lock. Handing out
// the runner's own slice would let that read race the next probe's write.
func TestForeignReturnsACopy(t *testing.T) {
	d, _ := newTestRunner(RoleStandalone)
	d.checkForeign(context.Background(), func(context.Context, time.Duration) ([]dhcpd.Foreign, error) {
		return []dhcpd.Foreign{{ServerID: netip.MustParseAddr("192.168.1.1")}}, nil
	})
	got := d.Foreign()
	got[0].ServerID = netip.MustParseAddr("10.0.0.1")
	if d.Foreign()[0].ServerID.String() != "192.168.1.1" {
		t.Fatal("Foreign() hands out the runner's own slice")
	}
}

// A watch that outlived its listener would go on probing a segment we no
// longer serve, and a banner that outlived it would accuse the operator of a
// conflict with a server that is no longer running.
func TestStoppingTheListenerEndsTheWatchAndClearsTheBanner(t *testing.T) {
	d, _ := newTestRunner(RoleStandalone)
	d.running = dhcpd.New(dhcpd.Options{})
	d.current = buildableSettings()
	stopped := false
	d.stopWatch = func() { stopped = true }
	d.foreign = []dhcpd.Foreign{{ServerID: netip.MustParseAddr("192.168.1.1")}}

	d.Reconcile(store.Settings{})

	if !stopped {
		t.Error("the periodic probe outlived the listener it was checking on")
	}
	if got := d.Foreign(); got != nil {
		t.Errorf("Foreign() = %+v after the listener stopped, want nothing to show", got)
	}
}

func TestWatchForeignStopsWithItsContext(t *testing.T) {
	d, _ := newTestRunner(RoleStandalone)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.watchForeign(ctx, func(context.Context, time.Duration) ([]dhcpd.Foreign, error) {
			t.Error("the probe ran after the listener stopped")
			return nil, nil
		})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watchForeign outlived its context, so it keeps probing a segment we no longer serve")
	}
}

// The watch is cancelled while a probe is already in flight on every stop, so
// its result must not land on a runner that has already let the listener go.
func TestAProbeInFlightWhenTheListenerStopsDoesNotRepopulateTheBanner(t *testing.T) {
	d, _ := newTestRunner(RoleStandalone)
	d.running = dhcpd.New(dhcpd.Options{})
	d.current = buildableSettings()
	ctx, cancel := context.WithCancel(context.Background())
	d.stopWatch = cancel

	d.checkForeign(ctx, func(context.Context, time.Duration) ([]dhcpd.Foreign, error) {
		d.Reconcile(store.Settings{}) // the listener goes down mid-probe
		return []dhcpd.Foreign{{ServerID: netip.MustParseAddr("192.168.1.1")}}, nil
	})

	if got := d.Foreign(); got != nil {
		t.Fatalf("Foreign() = %+v, want nothing: the listener it described is gone", got)
	}
}

// Revoking the override cannot take down a listener that is already serving
// the LAN — the same reasoning that keeps the periodic probe from doing it —
// but the save takes the unchanged-config early return, so without a line in
// the log an operator who has just found a server they do not trust gets no
// answer at all.
func TestRevokingTheOverrideWhileRunningSaysSo(t *testing.T) {
	d, _ := newTestRunner(RoleStandalone)
	var log bytes.Buffer
	d.logger = slog.New(slog.NewTextHandler(&log, nil))
	on := buildableSettings()
	on.DHCPAllowForeign = true
	d.running = dhcpd.New(dhcpd.Options{})
	d.current = on
	d.poller.SetSource(d.running)

	off := on
	off.DHCPAllowForeign = false
	d.Reconcile(off)

	if running, err := d.Status(); !running || err != nil {
		t.Fatalf("revoking the override: running=%v err=%v, want the listener left alone", running, err)
	}
	if !strings.Contains(log.String(), "override") {
		t.Errorf("revoking the override logged nothing: %q", log.String())
	}
	if !strings.Contains(log.String(), "restart") {
		t.Errorf("the log does not say when the change takes effect: %q", log.String())
	}

	// Once per transition: every later save of the same settings is silent.
	log.Reset()
	d.Reconcile(off)
	if log.Len() != 0 {
		t.Errorf("an unrelated later save logged the transition again: %q", log.String())
	}
}

// stopLocked must not reach the watch through running: the two are set in the
// same critical section today, so an early return that skips the cancel is
// latent rather than live, and latent-until-it-isn't leaks a goroutine
// probing a segment we no longer serve.
func TestStopLockedCancelsTheWatchWithNoListener(t *testing.T) {
	d, _ := newTestRunner(RoleStandalone)
	stopped := false
	d.stopWatch = func() { stopped = true }
	d.foreign = []dhcpd.Foreign{{ServerID: netip.MustParseAddr("192.168.1.1")}}

	d.mu.Lock()
	d.stopLocked()
	d.mu.Unlock()

	if !stopped {
		t.Error("stopLocked left the watch running because no listener was set")
	}
	if d.stopWatch != nil {
		t.Error("stopLocked left a spent cancel behind")
	}
	if got := d.Foreign(); got != nil {
		t.Errorf("Foreign() = %+v after stopLocked, want nothing to show", got)
	}
}

// ranWithin reports whether fn returned, so a lock taken twice fails a test
// rather than hanging it.
func ranWithin(fn func()) bool {
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
		return true
	case <-time.After(5 * time.Second):
		return false
	}
}

// reservedRunner is a runner holding a listener's allocator without a socket:
// everything reservations touch is reachable without a bind.
func reservedRunner(svcs []store.Service) (*dhcpRunner, *dhcpd.Allocator) {
	d, _ := newBuildableRunner(func(context.Context, string, time.Duration) ([]dhcpd.Foreign, error) {
		return nil, nil
	})
	info, _ := fakeIface("eth0")
	alloc := dhcpd.NewAllocator(dhcpd.Config{
		Subnet:    info.Subnet,
		Start:     netip.MustParseAddr("192.168.1.100"),
		End:       netip.MustParseAddr("192.168.1.200"),
		Host:      info.Addr,
		Gateway:   netip.MustParseAddr("192.168.1.1"),
		LeaseTime: time.Hour,
	}, time.Now)
	d.running = dhcpd.New(dhcpd.Options{})
	d.current = buildableSettings()
	d.alloc, d.subnet = alloc, info.Subnet
	d.services = func() ([]store.Service, error) { return svcs, nil }
	return d, alloc
}

// The lock rules pull against each other: Reconcile holds d.mu for its whole
// body, and the refresh reads the store, which must not run under it. Both
// are checked here because getting either wrong hangs the daemon at boot.
func TestReconcileRefreshesReservationsWithoutHoldingItsLock(t *testing.T) {
	d, alloc := reservedRunner([]store.Service{{
		Name: "kypost", MAC: "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{{Address: "192.168.1.20"}},
	}})
	svcs := d.services
	d.services = func() ([]store.Service, error) {
		// Status takes d.mu. Held across a database query, the whole UI
		// would block for the length of it.
		if !ranWithin(func() { d.Status() }) {
			t.Error("Status blocked while the service list was being read")
		}
		return svcs()
	}

	if !ranWithin(func() { d.Reconcile(d.current) }) {
		t.Fatal("Reconcile never returned; d.mu was taken twice")
	}

	l, ok := alloc.Allocate("aa:bb:cc:dd:ee:ff", "kypost", netip.Addr{}, time.Hour)
	if !ok || l.IP != netip.MustParseAddr("192.168.1.20") {
		t.Fatalf("the reserved client got %v (ok=%v), want its reservation", l.IP, ok)
	}
	if p := d.Problems(); len(p) != 0 {
		t.Errorf("Problems() = %+v, want none", p)
	}
}

// Reason is shown verbatim, so an inactive reservation has to tell the
// operator what to do about it.
func TestUnresolvedReservationsAreReportedForTheUI(t *testing.T) {
	d, _ := reservedRunner([]store.Service{{
		Name: "offsite", MAC: "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{{Address: "10.9.0.20"}},
	}})
	d.RefreshReservations()

	got := d.Problems()
	if len(got) != 1 || got[0].Service != "offsite" || got[0].Reason == "" {
		t.Fatalf("Problems() = %+v, want one entry naming offsite with a reason", got)
	}
	got[0].Service = "mutated"
	if d.Problems()[0].Service != "offsite" {
		t.Error("Problems() hands out the live report, so a caller can corrupt it")
	}
}

// The store read runs outside d.mu, so a stop can land in the middle of one.
// Publishing afterwards would show problems for a server no longer serving.
func TestAStopDuringARefreshDoesNotRepublishTheProblems(t *testing.T) {
	d, _ := reservedRunner([]store.Service{{
		Name: "offsite", MAC: "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{{Address: "10.9.0.20"}},
	}})
	svcs, reads := d.services, 0
	d.services = func() ([]store.Service, error) {
		reads++
		if reads == 1 {
			// Only on the outermost read: Reconcile reads the list too, to
			// seed the listener it may build, and re-entering on that one
			// would recurse forever without testing anything.
			d.Reconcile(store.Settings{}) // dhcp turned off mid-read
		}
		return svcs()
	}

	if !ranWithin(func() { d.RefreshReservations() }) {
		t.Fatal("the refresh never returned")
	}
	if p := d.Problems(); len(p) != 0 {
		t.Fatalf("Problems() = %+v after the listener stopped, want none", p)
	}
	// Nothing is running, so there is nothing to reserve for and no reason to
	// go back to the database.
	settled := reads
	d.RefreshReservations()
	if reads != settled {
		t.Fatalf("the service list was read again; a stopped runner still queries")
	}
}

// The staleness re-check has two halves for two different reasons the running
// listener can move under a refresh. This isolates the alloc half: reconcile
// (the locked half of Reconcile) clears d.alloc on a stop but never touches
// gen - only the public Reconcile's trailing RefreshReservations bumps that -
// so a stop landing mid-read must be caught by alloc alone, with gen equal
// throughout.
func TestTheAllocGuardCatchesAStopThatGenAloneWouldMiss(t *testing.T) {
	d, _ := reservedRunner([]store.Service{{
		Name: "offsite", MAC: "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{{Address: "10.9.0.20"}},
	}})
	svcs := d.services
	d.services = func() ([]store.Service, error) {
		// The locked reconcile, not the public Reconcile: it never calls
		// RefreshReservations, so gen stays exactly where this refresh
		// captured it.
		d.reconcile(store.Settings{}, nil)
		return svcs()
	}

	if !ranWithin(func() { d.RefreshReservations() }) {
		t.Fatal("the refresh never returned")
	}
	if p := d.Problems(); len(p) != 0 {
		t.Fatalf("Problems() = %+v after the listener stopped, want none", p)
	}
}

// A registry write refreshes while the UI reads. -race is the point of this
// one; it passes trivially without it.
func TestRefreshReservationsIsSafeAlongsideTheUIReads(t *testing.T) {
	d, _ := reservedRunner([]store.Service{{
		Name: "kypost", MAC: "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{{Address: "192.168.1.20"}},
	}})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(3)
		go func() { defer wg.Done(); d.RefreshReservations() }()
		go func() { defer wg.Done(); d.Problems() }()
		go func() { defer wg.Done(); d.Status() }()
	}
	wg.Wait()
}

// Two registry writes overlap: registry.onChange is not serialized, so a
// refresh that started first can finish last. Without a sequence number the
// older service list is published on top of the newer one and sticks there
// until the next write.
func TestAnOverlappingRefreshNeverPublishesTheOlderList(t *testing.T) {
	d, alloc := reservedRunner(nil)
	older := []store.Service{
		{Name: "kypost", MAC: "aa:bb:cc:dd:ee:ff",
			Addresses: []store.Address{{Address: "192.168.1.20"}}},
		{Name: "offsite", MAC: "11:22:33:44:55:66",
			Addresses: []store.Address{{Address: "10.9.0.20"}}},
	}
	newer := []store.Service{{Name: "kypost", MAC: "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{{Address: "192.168.1.21"}}}}

	var first sync.Once
	entered, release := make(chan struct{}), make(chan struct{})
	d.services = func() ([]store.Service, error) {
		oldest := false
		first.Do(func() { oldest = true })
		if !oldest {
			return newer, nil
		}
		close(entered)
		<-release // the second refresh overtakes while this one is reading
		return older, nil
	}

	done := make(chan struct{})
	go func() { defer close(done); d.RefreshReservations() }()
	<-entered
	d.RefreshReservations() // runs start to finish with the newer list
	close(release)
	<-done

	l, ok := alloc.Allocate("aa:bb:cc:dd:ee:ff", "kypost", netip.Addr{}, time.Hour)
	if !ok || l.IP != netip.MustParseAddr("192.168.1.21") {
		t.Fatalf("the client got %v (ok=%v); the service was moved to .21", l.IP, ok)
	}
	if p := d.Problems(); len(p) != 0 {
		t.Fatalf("Problems() = %+v, want none: offsite is gone from the newer list", p)
	}
}

// serve.go never sets d.start; a real node relies entirely on the nil default
// resolving to the real bind. Calling it would open :67, which no test here
// may do, so this checks function identity instead - the same technique
// proves the default without ever dialing a socket.
func TestANilStartHookDefaultsToTheRealListener(t *testing.T) {
	d := &dhcpRunner{}
	got := reflect.ValueOf(d.effectiveStart()).Pointer()
	want := reflect.ValueOf(startListener).Pointer()
	if got != want {
		t.Fatal("a nil start hook did not default to startListener; every DHCP-enabled node would panic at boot")
	}
}

// The one line the feature hangs on: Reconcile records the allocator it just
// built, and only after the listener binds. Recorded earlier, stopLocked wipes
// it; recorded nowhere, every reservation is silently inactive and the suite
// stays green. Start is injected because reaching that line otherwise takes
// :67, which no test here may hold.
func TestASuccessfulReconcileArmsTheNewAllocator(t *testing.T) {
	d, _ := newBuildableRunner(func(context.Context, string, time.Duration) ([]dhcpd.Foreign, error) {
		return nil, nil
	})
	d.start = func(built) error { return nil }
	d.services = func() ([]store.Service, error) {
		// Spelled as a legacy row: normalizing is what makes the wire find it.
		return []store.Service{{Name: "kypost", MAC: "AA-BB-CC-DD-EE-FF",
			Addresses: []store.Address{{Address: "192.168.1.20"}}}}, nil
	}
	d.Reconcile(buildableSettings())
	t.Cleanup(func() { d.Reconcile(store.Settings{}) })

	running, err := d.Status()
	if !running || err != nil {
		t.Fatalf("Status() = %v, %v; want a running listener and no reason", running, err)
	}
	if d.alloc == nil || d.subnet != netip.MustParsePrefix("192.168.1.0/24") {
		t.Fatalf("alloc=%v subnet=%v; the listener's allocator was not recorded", d.alloc, d.subnet)
	}
	l, ok := d.alloc.Allocate("aa:bb:cc:dd:ee:ff", "kypost", netip.Addr{}, time.Hour)
	if !ok || l.IP != netip.MustParseAddr("192.168.1.20") {
		t.Fatalf("the reserved client got %v (ok=%v), want its reservation", l.IP, ok)
	}
}

// The socket answers the first DISCOVER the instant it is open. Reservations
// that land afterwards leave a window where a stranger is handed a reserved
// address - and after a power cut the whole segment DISCOVERs at once, which
// is exactly when this reconcile runs.
func TestTheAllocatorIsArmedBeforeTheListenerBinds(t *testing.T) {
	d, _ := newBuildableRunner(func(context.Context, string, time.Duration) ([]dhcpd.Foreign, error) {
		return nil, nil
	})
	// Inside the pool, so an unarmed allocator would hand it straight out.
	reserved := netip.MustParseAddr("192.168.1.100")
	d.services = func() ([]store.Service, error) {
		return []store.Service{{Name: "kypost", MAC: "aa:bb:cc:dd:ee:ff",
			Addresses: []store.Address{{Address: reserved.String()}}}}, nil
	}
	var atBind netip.Addr
	d.start = func(b built) error {
		// The first DISCOVER on the socket this call is about to open.
		l, _, _ := b.alloc.Offer("99:99:99:99:99:99", netip.Addr{}, time.Minute)
		atBind = l.IP
		return nil
	}
	d.Reconcile(buildableSettings())
	t.Cleanup(func() { d.Reconcile(store.Settings{}) })

	if atBind == reserved {
		t.Fatalf("the first DISCOVER after the bind was offered %v, which is kypost's reservation", atBind)
	}
}
