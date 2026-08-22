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
	// services reads the current service list. Reservations are derived from
	// it, so a registry write and a settings save both come through here.
	services func() ([]store.Service, error)
	// Injected for tests: the decisions that refuse a start are host-state
	// calls, and a test must be able to reach them without an interface or a
	// socket. Nil means the real one.
	qualifies     func(string) error
	inspect       func(string) (dhcpd.IfaceInfo, error)
	detectForeign func(context.Context, string, time.Duration) ([]dhcpd.Foreign, error)
	// start binds the listener. Everything Reconcile does after a successful
	// bind is unreachable without this, because no test may hold :67. It takes
	// the whole built value so a test can see the state the socket opens on.
	start func(built) error

	mu      sync.Mutex
	running *dhcpd.Server
	current store.Settings
	// lastError is what the UI shows when DHCP is configured but not running.
	lastError error
	// foreign is the last periodic probe result, for the UI banner. It never
	// stops the listener: pulling DHCP out from under a working network over
	// one transient answer is worse than the conflict it reacts to.
	foreign []dhcpd.Foreign
	// stopWatch ends the periodic probe when the listener stops.
	stopWatch context.CancelFunc
	// alloc and subnet belong to the running listener, held so reservations
	// refresh without rebuilding it. Nil alloc means nothing is running and
	// there is nothing to reserve for.
	alloc  *dhcpd.Allocator
	subnet netip.Prefix
	// gen counts refreshes. Nothing serializes them - two registry writes
	// overlap freely - so a refresh that started first can finish last, and
	// publishing its list would leave the allocator on stale service data
	// until the next write.
	gen uint64
	// problems is the last unresolved-reservation report, for the UI.
	problems []dhcpd.ReservationProblem
}

// foreignProbe is one run of the rogue check. A func rather than the server
// itself, so the watch is driven in a test without a socket.
type foreignProbe func(context.Context, time.Duration) ([]dhcpd.Foreign, error)

const (
	// foreignWatchEvery is how often a running server re-checks for company.
	foreignWatchEvery = 15 * time.Minute
	// foreignProbeWait is how long each probe listens for OFFERs.
	foreignProbeWait = 2 * time.Second
)

// Reconcile brings the listener in line with v. It is safe to call with
// unchanged settings: an already-correct listener is left alone.
//
// The service list is read here and the refresh sequenced after, because
// reconcile holds d.mu for its whole body and reading the store under it
// would block Status and every settings save for the length of a query. The
// list read up front seeds a new listener before it binds; the refresh after
// is what reports the problems and covers the paths that built nothing.
func (d *dhcpRunner) Reconcile(v store.Settings) {
	svcs, err := d.services()
	if err != nil {
		// Not fatal to the listener: DHCP without reservations still serves
		// the LAN, and the refresh below retries and reports.
		d.logger.Error("could not read services to seed DHCP reservations", "error", err)
	}
	d.reconcile(v, svcs)
	d.RefreshReservations()
}

func (d *dhcpRunner) reconcile(v store.Settings, svcs []store.Service) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !dhcpWanted(v, d.role()) {
		d.stopLocked()
		d.current, d.lastError = v, roleRefusal(v, d.role())
		return
	}
	if d.running != nil && dhcpConfigEqual(d.current, v) {
		if d.current.DHCPAllowForeign && !v.DHCPAllowForeign {
			// Same reasoning as the periodic probe: never pull DHCP out from
			// under a working network. Say so, though — an operator revoking
			// this has just found a server they do not trust.
			d.logger.Info("dhcp foreign-server override revoked; the running listener is unaffected until the next restart or reconfigure")
			d.current.DHCPAllowForeign = false // so the transition logs once
		}
		// The listener already runs exactly this, so any earlier refusal is
		// spent: leaving it would report "running yes" beside a stale reason.
		d.lastError = nil
		return
	}
	// Build before stop: a build that refuses must leave the listener that is
	// already serving the LAN alone. Reconcile has three triggers — boot, a
	// settings save, and promotion — so a stop here would have no retry.
	b, err := d.build(v, d.needsProbe(v))
	if err != nil {
		d.fail(v, err, "dhcp is enabled but cannot start")
		return
	}
	// Armed before it binds. A listener answers the first DISCOVER the moment
	// the socket is open, and an allocator with no reservations yet would hand
	// a reserved address to whoever asked first - which after a power cut is
	// the whole segment at once. Reservations is pure, so this is safe under
	// d.mu; the problems it found are reported by the refresh that follows.
	res, _ := dhcpd.Reservations(svcs, b.subnet)
	b.alloc.SetReservations(res)
	// The old listener holds :67 until it is closed, so it goes down only once
	// its replacement is built and about to bind.
	d.stopLocked()
	start := d.start
	if start == nil {
		start = startListener
	}
	if err := start(b); err != nil {
		d.fail(v, err, "dhcp listener failed to bind")
		return
	}
	d.running, d.current, d.lastError = b.srv, v, nil
	// Recorded here, not in build: stopLocked runs between the two and clears
	// them, and a build that never bound must not leave its allocator behind
	// for the refresh to feed.
	d.alloc, d.subnet = b.alloc, b.subnet
	d.poller.SetSource(b.srv)
	watchCtx, cancel := context.WithCancel(context.Background())
	d.stopWatch = cancel
	go d.watchForeign(watchCtx, b.srv.ProbeForeign)
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

// startListener is the real bind. Named so the injected form has something to
// default to; see dhcpRunner.start.
func startListener(b built) error { return b.srv.Start(context.Background()) }

// built is a listener and the two pieces Reconcile keeps once it binds: its
// allocator, so reservations refresh without a rebuild, and the subnet they
// resolve against.
type built struct {
	srv    *dhcpd.Server
	alloc  *dhcpd.Allocator
	subnet netip.Prefix
}

// build assembles a server, refusing on anything the operator must fix first.
// probe is false only when a listener is already bound to this interface.
func (d *dhcpRunner) build(v store.Settings, probe bool) (built, error) {
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
		return built{}, err
	}
	info, err := inspect(v.DHCPInterface)
	if err != nil {
		return built{}, err
	}
	// Parsed, not asserted: build runs against whatever is in the settings
	// row, including one written before the validator existed or edited by
	// hand in SQLite. A bad value is a reportable setting, not a panic.
	start, err := parseSetting("dhcp.range_start", v.DHCPRangeStart)
	if err != nil {
		return built{}, err
	}
	end, err := parseSetting("dhcp.range_end", v.DHCPRangeEnd)
	if err != nil {
		return built{}, err
	}
	gateway, err := parseSetting("dhcp.gateway", v.DHCPGateway)
	if err != nil {
		return built{}, err
	}
	// The validator cannot check this: it never reads host state, so the same
	// row validates identically on every node. Here is the only place that
	// holds both the range and the live interface. Out-of-subnet addresses
	// would be handed out and no client on the segment could use them.
	if !info.Subnet.Contains(start) || !info.Subnet.Contains(end) {
		return built{}, fmt.Errorf(
			"the DHCP range %s-%s is not inside %s, the subnet of interface %q",
			start, end, info.Subnet, v.DHCPInterface)
	}

	// The rogue check is a start-time gate, not a periodic one; re-checking a
	// live segment is watchForeign's job.
	if probe {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		foreign, probeErr := detect(ctx, v.DHCPInterface, foreignProbeWait)
		if probeErr != nil {
			// Named here rather than in foreignVerdict: on a multi-homed host
			// "the probe failed" is half an answer without the segment.
			probeErr = fmt.Errorf("interface %q: %w", v.DHCPInterface, probeErr)
		}
		if err := foreignVerdict(foreign, probeErr, v.DHCPAllowForeign); err != nil {
			return built{}, err
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
			return built{}, err
		}
		dns = append(dns, a)
	}
	alloc := dhcpd.NewAllocator(cfg, time.Now)
	return built{
		srv: dhcpd.New(dhcpd.Options{
			Iface:    info,
			Cfg:      cfg,
			DNS:      dns,
			Domain:   v.PrivateDomain,
			Alloc:    alloc,
			Prober:   dhcpd.NewProber(v.DHCPInterface, 100*time.Millisecond),
			Store:    d.store,
			OnChange: d.onChange,
			Logger:   d.logger,
		}),
		alloc:  alloc,
		subnet: info.Subnet,
	}, nil
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
	// Unconditional: a watch or a banner that outlived its listener would go
	// on describing a segment we no longer serve, so neither may depend on
	// running being set.
	if d.stopWatch != nil {
		d.stopWatch()
		d.stopWatch = nil
	}
	d.foreign = nil
	// Reservation state belongs to the listener: leaving it would go on
	// reporting a segment we no longer serve, and would feed an allocator
	// nothing reads.
	d.alloc, d.subnet, d.problems = nil, netip.Prefix{}, nil
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

// RefreshReservations re-derives reservations from the current services. It
// is called after every registry write, because renaming or re-addressing a
// service changes what its reservation resolves to.
//
// d.mu is taken twice, around the store read rather than across it: a
// database query under it would block Status, Foreign and every settings save
// for its duration. Anything can therefore happen mid-read, so nothing is
// published until the second section has checked that this refresh is still
// the current one - the listener may have gone down, and a later refresh may
// have already finished with a newer list.
func (d *dhcpRunner) RefreshReservations() {
	d.mu.Lock()
	d.gen++
	gen, alloc, subnet := d.gen, d.alloc, d.subnet
	d.mu.Unlock()
	if alloc == nil {
		return // nothing is running, so there is nothing to reserve for
	}
	svcs, err := d.services()
	if err != nil {
		d.logger.Error("could not read services to refresh DHCP reservations", "error", err)
		return
	}
	res, problems := dhcpd.Reservations(svcs, subnet)

	d.mu.Lock()
	if d.alloc != alloc || d.gen != gen {
		// The listener went down while we read, or a later refresh overtook
		// this one: either way this describes a service list we have already
		// moved past.
		d.mu.Unlock()
		return
	}
	// Under the lock with the publish it belongs to, so the allocator and the
	// report can never end up describing different reads.
	alloc.SetReservations(res)
	d.problems = problems
	d.mu.Unlock()
	for _, p := range problems {
		d.logger.Warn("a DHCP reservation is inactive",
			"service", p.Service, "mac", p.MAC, "reason", p.Reason)
	}
}

// Problems returns the last unresolved-reservation report, for the UI.
func (d *dhcpRunner) Problems() []dhcpd.ReservationProblem {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]dhcpd.ReservationProblem(nil), d.problems...)
}

// Status is what the API and the UI report.
func (d *dhcpRunner) Status() (running bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running != nil, d.lastError
}

// watchForeign warns about another DHCP server appearing after we started.
// It only ever logs and populates the banner.
func (d *dhcpRunner) watchForeign(ctx context.Context, probe foreignProbe) {
	t := time.NewTicker(foreignWatchEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d.checkForeign(ctx, probe)
	}
}

// checkForeign runs one periodic probe. A probe that could not run leaves the
// last result alone rather than clearing it: "we could not check" is not "all
// clear", and this one has no operator in front of it to say so to.
func (d *dhcpRunner) checkForeign(ctx context.Context, probe foreignProbe) {
	found, err := probe(ctx, foreignProbeWait)
	if err != nil {
		d.logger.Warn("periodic dhcp conflict probe failed", "error", err)
		return
	}
	d.mu.Lock()
	// Checked under the lock: stopLocked cancels this context and clears the
	// banner in the same section, so an in-flight probe must not write its
	// result back afterwards and describe a listener that is gone.
	if ctx.Err() == nil {
		d.foreign = found
	}
	d.mu.Unlock()
	for _, f := range found {
		d.logger.Warn("another DHCP server is answering on this network",
			"server", f.ServerID.String(), "offered", f.Offered.String())
	}
}

// Foreign returns the last periodic probe result, for the UI banner.
func (d *dhcpRunner) Foreign() []dhcpd.Foreign {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.foreign) == 0 {
		return nil
	}
	return append([]dhcpd.Foreign(nil), d.foreign...)
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

// foreignVerdict decides whether a probe result blocks the start. The
// override exists for operators who genuinely run two servers - split scopes,
// a deliberate second scope on another VLAN - and is off by default because
// the failure it guards against takes down the whole network rather than one
// name.
//
// One key covers both refusals. A probe that could not run says we do not know
// whether another server is there, and that is fatal precisely so it is never
// mistaken for a clear. The operator who wants past that is the same operator
// who wants past a detected server - most often the one whose own DHCP client
// already holds :68 - so two boxes would be ceremony, not safety.
func foreignVerdict(found []dhcpd.Foreign, probeErr error, allow bool) error {
	if allow {
		return nil
	}
	if probeErr != nil {
		return fmt.Errorf("could not check whether another DHCP server is already answering, so refusing to start: %w", probeErr)
	}
	if len(found) == 0 {
		return nil
	}
	return &ForeignServerError{Found: found}
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
