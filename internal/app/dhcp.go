package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/dhcpd"
	"github.com/yoshiofthewire/kydns-server/internal/discovery"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// dhcpWanted reports whether the built-in server should be running. A replica
// never serves DHCP whatever its local settings say: two DHCP servers on one
// segment is the failure this protects against, and a replica's whole job is
// to be a second node on the same network. Every other role may serve, which
// includes the standalone node most installs actually are.
func dhcpWanted(v store.Settings, role Role) bool {
	return v.DHCPEnabled && v.DHCPInterface != "" && role != RoleReplica
}

// dhcpRunner owns the listener's lifecycle. Reconcile is idempotent and is
// the only way the listener starts or stops, so a settings save, a promotion,
// and boot all take the same path.
type dhcpRunner struct {
	poller *discovery.Poller
	store  dhcpd.LeaseStore
	logger *slog.Logger
	// onChange rebuilds the zone snapshot when the lease set moves.
	onChange func()
	// role is read at every Reconcile, so a promotion starts DHCP without a
	// restart.
	role func() Role
	// Injected for tests: the decisions that refuse a start are host-state
	// calls, and a test must be able to reach them without an interface or a
	// socket. Nil means the real one.
	qualifies     func(string) error
	inspect       func(string) (dhcpd.IfaceInfo, error)
	detectForeign func(context.Context, string, time.Duration) ([]dhcpd.Foreign, error)

	mu      sync.Mutex
	running *dhcpd.Server
	current store.Settings
	// lastError is what the UI shows when DHCP is configured but not running.
	lastError error
}

// Reconcile brings the listener in line with v. It is safe to call with
// unchanged settings: an already-correct listener is left alone.
func (d *dhcpRunner) Reconcile(v store.Settings) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !dhcpWanted(v, d.role()) {
		d.stopLocked()
		d.current, d.lastError = v, roleRefusal(v, d.role())
		return
	}
	if d.running != nil && dhcpConfigEqual(d.current, v) {
		return
	}
	// Build before stop: a build that refuses must leave the listener that is
	// already serving the LAN alone. Reconcile has three triggers — boot, a
	// settings save, and promotion — so a stop here would have no retry.
	srv, err := d.build(v, d.needsProbe(v))
	if err != nil {
		d.fail(v, err, "dhcp is enabled but cannot start")
		return
	}
	// The old listener holds :67 until it is closed, so it goes down only once
	// its replacement is built and about to bind.
	d.stopLocked()
	if err := srv.Start(context.Background()); err != nil {
		d.fail(v, err, "dhcp listener failed to bind")
		return
	}
	d.running, d.current, d.lastError = srv, v, nil
	d.poller.SetSource(srv)
	d.logger.Info("dhcp server started",
		"interface", v.DHCPInterface, "range", v.DHCPRangeStart+"-"+v.DHCPRangeEnd)
}

// needsProbe reports whether this build must run the rogue check. A listener
// already bound to this interface cleared that segment when it started and is
// holding it now, so probing again would only risk a transient answer taking a
// working server down. Re-checking a live segment is the periodic probe's job.
func (d *dhcpRunner) needsProbe(v store.Settings) bool {
	return d.running == nil || d.current.DHCPInterface != v.DHCPInterface
}

// fail records why the listener is not what the settings ask for. current is
// left alone while a listener is still up, so it keeps describing the one that
// is actually running and the next save retries the build.
func (d *dhcpRunner) fail(v store.Settings, err error, msg string) {
	d.lastError = err
	d.logger.Error(msg, "error", err)
	if d.running == nil {
		d.current = v
	}
}

// roleRefusal is why DHCP is off when the operator asked for it on. A replica
// that reported no reason at all would look broken rather than correct.
func roleRefusal(v store.Settings, role Role) error {
	if v.DHCPEnabled && v.DHCPInterface != "" && role == RoleReplica {
		return errReplicaNoDHCP
	}
	return nil
}

var errReplicaNoDHCP = errors.New(
	"this node is a replica, so it does not serve DHCP: two DHCP servers on one " +
		"network breaks it. The primary serves DHCP; a replica does after it is promoted")

// build assembles a server, refusing on anything the operator must fix first.
// probe is false only when a listener is already bound to this interface.
func (d *dhcpRunner) build(v store.Settings, probe bool) (*dhcpd.Server, error) {
	qualifies, inspect, detect := d.qualifies, d.inspect, d.detectForeign
	if qualifies == nil {
		qualifies = dhcpd.Qualifies
	}
	if inspect == nil {
		inspect = dhcpd.Inspect
	}
	if detect == nil {
		detect = dhcpd.DetectForeign
	}
	if err := qualifies(v.DHCPInterface); err != nil {
		return nil, err
	}
	info, err := inspect(v.DHCPInterface)
	if err != nil {
		return nil, err
	}
	// Parsed, not asserted: build runs against whatever is in the settings
	// row, including one written before the validator existed or edited by
	// hand in SQLite. A bad value is a reportable setting, not a panic.
	start, err := parseSetting("dhcp.range_start", v.DHCPRangeStart)
	if err != nil {
		return nil, err
	}
	end, err := parseSetting("dhcp.range_end", v.DHCPRangeEnd)
	if err != nil {
		return nil, err
	}
	gateway, err := parseSetting("dhcp.gateway", v.DHCPGateway)
	if err != nil {
		return nil, err
	}
	// The validator cannot check this: it never reads host state, so the same
	// row validates identically on every node. Here is the only place that
	// holds both the range and the live interface. Out-of-subnet addresses
	// would be handed out and no client on the segment could use them.
	if !info.Subnet.Contains(start) || !info.Subnet.Contains(end) {
		return nil, fmt.Errorf(
			"the DHCP range %s-%s is not inside %s, the subnet of interface %q",
			start, end, info.Subnet, v.DHCPInterface)
	}

	// The rogue check is a start-time gate, not a periodic one. A positive
	// result refuses: two servers on one segment breaks the network. So does
	// an error — it means we do not know whether another server is there, and
	// guessing "no" would drop the protection on exactly the hosts where the
	// probe is hardest to run.
	if probe {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		foreign, err := detect(ctx, v.DHCPInterface, 2*time.Second)
		if err != nil {
			return nil, fmt.Errorf(
				"could not check whether another DHCP server is already answering on %q, so refusing to start: %w",
				v.DHCPInterface, err)
		}
		if len(foreign) > 0 {
			return nil, &ForeignServerError{Found: foreign}
		}
	}

	cfg := dhcpd.Config{
		Subnet:    info.Subnet,
		Start:     start,
		End:       end,
		Host:      info.Addr,
		Gateway:   gateway,
		LeaseTime: time.Duration(v.DHCPLeaseSeconds) * time.Second,
	}
	dns := []netip.Addr{info.Addr}
	if strings.TrimSpace(v.DHCPSecondaryDNS) != "" {
		// Dropping this silently would quietly undo the second resolver the
		// operator configured, on the save that turns DHCP on.
		a, err := parseSetting("dhcp.secondary_dns", v.DHCPSecondaryDNS)
		if err != nil {
			return nil, err
		}
		dns = append(dns, a)
	}
	return dhcpd.New(dhcpd.Options{
		Iface:    info,
		Cfg:      cfg,
		DNS:      dns,
		Domain:   v.PrivateDomain,
		Alloc:    dhcpd.NewAllocator(cfg, time.Now),
		Prober:   dhcpd.NewProber(v.DHCPInterface, 100*time.Millisecond),
		Store:    d.store,
		OnChange: d.onChange,
		Logger:   d.logger,
	}), nil
}

// parseSetting names the field, because "invalid IP" on its own sends an
// operator reading three of them.
func parseSetting(key, value string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%s: %q is not an IP address", key, value)
	}
	return a, nil
}

func (d *dhcpRunner) stopLocked() {
	if d.running == nil {
		return
	}
	if err := d.running.Stop(); err != nil {
		d.logger.Warn("dhcp listener did not close cleanly", "error", err)
	}
	d.running = nil
	d.poller.SetSource(nil)
	d.logger.Info("dhcp server stopped")
}

// Status is what the API and the UI report.
func (d *dhcpRunner) Status() (running bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running != nil, d.lastError
}

// dhcpConfigEqual reports whether two settings would produce the same
// listener. Every field the server is built from is here; anything missing
// would silently fail to apply.
func dhcpConfigEqual(a, b store.Settings) bool {
	return a.DHCPEnabled == b.DHCPEnabled &&
		a.DHCPInterface == b.DHCPInterface &&
		a.DHCPRangeStart == b.DHCPRangeStart &&
		a.DHCPRangeEnd == b.DHCPRangeEnd &&
		a.DHCPGateway == b.DHCPGateway &&
		a.DHCPLeaseSeconds == b.DHCPLeaseSeconds &&
		a.DHCPSecondaryDNS == b.DHCPSecondaryDNS &&
		a.PrivateDomain == b.PrivateDomain
}

// ForeignServerError names the other DHCP server, because "could not start"
// on its own sends an operator hunting.
type ForeignServerError struct{ Found []dhcpd.Foreign }

func (e *ForeignServerError) Error() string {
	names := make([]string, 0, len(e.Found))
	for _, f := range e.Found {
		names = append(names, f.String())
	}
	return "another DHCP server is already answering on this network: " +
		strings.Join(names, ", ") +
		". Turn it off there first, then enable the built-in server again"
}
