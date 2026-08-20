### Task 10: Runtime wiring

The poller is now always constructed and always running, the DHCP server starts and stops on a settings change, and packaging grants the capability the socket needs.

**Files:**
- Modify: `internal/app/serve.go:81-152`, `:337-339`; `internal/app/apply.go:20-40` and `Apply`
- Modify: `packaging/` systemd unit
- Test: `internal/app/dhcp_test.go`

**Interfaces:**
- Consumes: `dhcpd.New`, `dhcpd.Qualifies`, `dhcpd.DetectForeign`, `dhcpd.NewAllocator`, `dhcpd.Inspect`, `discovery.Poller.SetSource`.
- Produces: `type dhcpRunner struct` in `internal/app`, with `func (d *dhcpRunner) Reconcile(v store.Settings)` — idempotent, called at boot and on every settings change.

- [ ] **Step 1: Write the failing tests**

Create `internal/app/dhcp_test.go`:

```go
package app

import (
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func TestDHCPWantedOnlyWhenEnabledAndPrimary(t *testing.T) {
	cases := []struct {
		name    string
		enabled bool
		iface   string
		role    Role
		want    bool
	}{
		{"enabled on a primary", true, "eth0", RolePrimary, true},
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
```

Check `internal/app/role.go` for the actual `Role` constant names before pasting — the test must use whatever `RoleAtBoot` returns, not names invented here.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/app/ -run TestDHCPWanted -v`
Expected: FAIL to compile with `undefined: dhcpWanted`.

- [ ] **Step 3: Write the runner**

Create `internal/app/dhcp.go`:

```go
package app

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/dhcpd"
	"github.com/yoshiofthewire/kydns-server/internal/discovery"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// dhcpWanted reports whether the built-in server should be running. A replica
// never serves DHCP whatever its local settings say: two DHCP servers on one
// segment is the failure this protects against, and a replica's whole job is
// to be a second node on the same network.
func dhcpWanted(v store.Settings, role Role) bool {
	return v.DHCPEnabled && v.DHCPInterface != "" && role == RolePrimary
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

	want := dhcpWanted(v, d.role())
	if !want {
		d.stopLocked()
		d.current, d.lastError = v, nil
		return
	}
	if d.running != nil && dhcpConfigEqual(d.current, v) {
		return
	}
	d.stopLocked()

	srv, err := d.build(v)
	if err != nil {
		d.lastError = err
		d.logger.Error("dhcp is enabled but cannot start", "error", err)
		d.current = v
		return
	}
	if err := srv.Start(context.Background()); err != nil {
		d.lastError = err
		d.logger.Error("dhcp listener failed to bind", "error", err)
		d.current = v
		return
	}
	d.running, d.current, d.lastError = srv, v, nil
	d.poller.SetSource(srv)
	d.logger.Info("dhcp server started",
		"interface", v.DHCPInterface, "range", v.DHCPRangeStart+"-"+v.DHCPRangeEnd)
}

// build assembles a server, refusing on anything the operator must fix first.
func (d *dhcpRunner) build(v store.Settings) (*dhcpd.Server, error) {
	if err := dhcpd.Qualifies(v.DHCPInterface); err != nil {
		return nil, err
	}
	info, err := dhcpd.Inspect(v.DHCPInterface)
	if err != nil {
		return nil, err
	}
	// The rogue check is a start-time gate, not a periodic one. A positive
	// result refuses: two servers on one segment breaks the network.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	foreign, err := dhcpd.DetectForeign(ctx, v.DHCPInterface, 2*time.Second, info.Addr)
	if err != nil {
		d.logger.Warn("could not probe for another dhcp server; starting anyway", "error", err)
	} else if len(foreign) > 0 {
		return nil, &ForeignServerError{Found: foreign}
	}

	cfg := dhcpd.Config{
		Subnet:    info.Subnet,
		Start:     netip.MustParseAddr(v.DHCPRangeStart),
		End:       netip.MustParseAddr(v.DHCPRangeEnd),
		Host:      info.Addr,
		Gateway:   netip.MustParseAddr(v.DHCPGateway),
		LeaseTime: time.Duration(v.DHCPLeaseSeconds) * time.Second,
	}
	dns := []netip.Addr{info.Addr}
	if v.DHCPSecondaryDNS != "" {
		if a, err := netip.ParseAddr(v.DHCPSecondaryDNS); err == nil {
			dns = append(dns, a)
		}
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
```

Add the error type in the same file:

```go
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
		". Turn it off there first, or enable the override if you run two deliberately"
}
```

Add `"strings"` to the imports.

- [ ] **Step 4: Always construct and run the poller**

In `internal/app/serve.go`, replace the conditional construction at line 146:

```go
	// The poller always exists and always runs: its source is swapped at
	// runtime, which is what lets both dhcp_lease_file and the built-in
	// server be turned on and off without a restart.
	poller = discovery.NewPoller(
		nil,
		time.Duration(boot.DiscoveryInterval)*time.Second,
		func() {
			if err := holder.Rebuild(); err != nil {
				logger.Error("rebuild after lease change failed", "error", err)
			}
		}, logger)
	if boot.DHCPLeaseFile != "" {
		poller.SetSource(&dhcp.DnsmasqSource{Path: boot.DHCPLeaseFile})
	}
```

Then simplify every `if poller != nil` guard in the file (lines 97, 245, 314, 337) — the poller is never nil now. The `go poller.Run(ctx)` at line 338 becomes unconditional.

- [ ] **Step 5: Reconcile from Apply**

In `internal/app/apply.go`, add the field to `liveComponents`:

```go
	dhcp          *dhcpRunner // nil in tests that do not build one
```

and at the end of `Apply`, before the final log line:

```go
	// The lease source follows the settings: built-in, lease file, or
	// neither. Reconcile is idempotent, so an unchanged configuration is a
	// no-op rather than a restart of a working listener.
	if l.dhcp != nil {
		l.dhcp.Reconcile(s.Raw)
	}
	if !s.Raw.DHCPEnabled {
		if s.Raw.DHCPLeaseFile != "" {
			l.poller.SetSource(&dhcp.DnsmasqSource{Path: s.Raw.DHCPLeaseFile})
		} else {
			l.poller.SetSource(nil)
		}
	}
	l.poller.SetInterval(time.Duration(s.Raw.DiscoveryInterval) * time.Second)
```

Remove the old `if l.poller != nil` guard around `SetInterval`. Add the `discovery/dhcp` import.

- [ ] **Step 6: Construct the runner in Serve**

In `internal/app/serve.go`, after the poller is built and before `liveComponents` is assembled:

```go
	dhcpRun := &dhcpRunner{
		poller: poller,
		store:  st,
		logger: logger,
		onChange: func() {
			if err := poller.Poll(ctx); err != nil {
				logger.Warn("lease refresh after a dhcp change failed", "error", err)
			}
		},
		role: func() Role { return roleHolder.Role() },
	}
	dhcpRun.Reconcile(snap.Raw)
```

Use whatever accessor `internal/app/role.go` actually exposes for the current role; if the role is held in a plain variable rather than behind an accessor, close over that variable instead. Pass `dhcp: dhcpRun` into the `liveComponents` literal at line 197.

- [ ] **Step 7: Grant the capability in packaging**

In the systemd unit under `packaging/`, add to the `[Service]` section:

```ini
# Port 67 is privileged, and the DHCP listener binds it as the unprivileged
# kydns user. No raw sockets: every DHCP reply is broadcast.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

If `AmbientCapabilities` is already present for port 53, add `CAP_NET_BIND_SERVICE` to the existing list rather than adding a second directive.

- [ ] **Step 8: Run the tests**

Run: `go build ./... && go test ./internal/app/... -v`
Expected: PASS. The pre-existing `serve_test.go` and `apply_test.go` are the real check here — they exercise the wiring you just changed.

- [ ] **Step 9: Run the whole suite**

Run: `go test ./... -count=1`
Expected: PASS. Task 1 changed a shared component; this is where a regression in lease-file discovery would surface.

- [ ] **Step 10: Commit**

```bash
git add internal/app/ packaging/
git commit -m "feat(app): start and stop the DHCP listener from settings

The poller now always exists and always runs, with its source swapped at
runtime - so both the built-in server and dhcp_lease_file apply without a
restart. Reconcile is idempotent and is the only path that binds or
closes the listener, so boot, a settings save, and a promotion all agree.

A replica never serves DHCP whatever its local settings say."
```

---

