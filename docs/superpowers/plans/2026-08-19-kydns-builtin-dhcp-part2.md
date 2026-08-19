# Built-in DHCPv4 Server — Part 2: reservations and the operator surface

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the working DHCP server from Part 1 into something an operator can run from the web UI — reservations that are services, a one-confirm setup wizard, a live lease table, and the honest notes about what the feature does not cover.

**Architecture:** A reservation is an optional MAC on a `Service`; the reserved address is derived, not stored, from the unique service address inside the DHCP subnet. Reservation resolution is a pure function in `internal/dhcpd` so it is tested without a network or a database. The web tab is one page following the existing `blacklists.html` pattern.

**Tech Stack:** Go 1.26.5, `html/template`, modernc SQLite, `net/netip`.

**Spec:** `docs/superpowers/specs/2026-08-19-kydns-builtin-dhcp-design.md`

**Depends on:** `docs/superpowers/plans/2026-08-19-kydns-builtin-dhcp-part1.md`, complete and merged. Part 1's Task 5 ships `Allocator.SetReservations` unused; this plan is what feeds it.

## Global Constraints

Every task's requirements implicitly include these, and Part 1's constraints still apply in full.

- **The reserved address is the unique service address inside the DHCP subnet.** Zero such addresses, or more than one, and the reservation is **inactive and flagged in the UI** — never guessed at.
- **MACs normalize to lowercase colon-separated form** and are unique across services. Use Part 1's `dhcpd.normalizeMAC`; do not write a second normalizer.
- **Reservations replicate** — they are service configuration, so the `cv_services_*` triggers already cover them. This is the opposite of the DHCP settings and is deliberate: a promoted replica must have them.
- **The periodic rogue probe warns and never disables** the listener.
- **The dual-stack note is informational, never a blocker.**
- Tests must not open a real DHCP socket.
- Commit at the end of every task.

---

## File Structure

**Created**

| File | Responsibility |
|---|---|
| `internal/dhcpd/reserve.go` | Resolve services into MAC-to-address reservations. Pure; no I/O. |
| `internal/web/dhcp.go` | The DHCP tab's handlers. |
| `internal/web/templates/dhcp.html` | The tab. |

**Modified**

| File | Change |
|---|---|
| `internal/store/model.go` | `Service.MAC`. |
| `internal/store/store.go` | `services.mac` column, `dhcp_allow_foreign` settings column, migration. |
| `internal/registry/validate.go` | `ValidateMAC`. |
| `internal/registry/registry.go` | MAC validation and uniqueness in `validateService`. |
| `internal/app/dhcp.go` | Feed reservations; the override; the periodic probe. |
| `internal/adminapi/settings.go`, `.../services.go`, `.../dhcp.go` | MAC field, reservation status, the wizard endpoint. |
| `internal/cli/settings.go` | The override key; `--mac` on service commands. |
| `internal/web/pages.go` | Register the tab. |
| `README.md`, `DESGINE.md`, `SECURITY.md`, `docs/superpowers/specs/2026-08-13-kydns-settings-in-the-ui-design.md` | Documentation. |

---

### Task 1: The foreign-server override and the periodic probe

This closes the gap Part 1's self-review named: `dhcpRunner.build` currently refuses on any foreign server with no way past it, which is stricter than the spec. It lands first because it is the last piece of safety behaviour, and everything after it is surface.

**Files:**
- Modify: `internal/store/model.go`, `internal/store/store.go` (schema + migration), `internal/store/settings.go`, `internal/settings/validate.go`, `internal/app/dhcp.go`
- Test: `internal/app/dhcp_test.go`, `internal/store/settings_test.go`

**Interfaces:**
- Produces: `store.Settings.DHCPAllowForeign bool`; `dhcpRunner.Foreign() []dhcpd.Foreign` for the UI banner.

- [ ] **Step 1: Write the failing tests**

Add to `internal/app/dhcp_test.go`:

```go
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
	if err := foreignVerdict(found, false); err == nil {
		t.Fatal("a foreign DHCP server was accepted without an override")
	}
	if err := foreignVerdict(found, true); err != nil {
		t.Fatalf("the override did not take: %v", err)
	}
	if err := foreignVerdict(nil, false); err != nil {
		t.Fatalf("a clear probe was treated as a failure: %v", err)
	}
}
```

Add to `internal/store/settings_test.go`, inside the existing `TestSettingsRoundTripsDHCPFields`, one more assignment before the write:

```go
	v.DHCPAllowForeign = true
```

The existing `got != v` comparison then covers it.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/app/ ./internal/store/ -run 'Foreign|DHCPFields' -v`
Expected: FAIL to compile with `undefined: foreignVerdict` and `v.DHCPAllowForeign undefined`.

- [ ] **Step 3: Add the setting**

In `internal/store/model.go`, add to the DHCP block in `Settings`:

```go
	DHCPAllowForeign bool
```

In `internal/store/store.go`, add to the base `settings` schema:

```sql
  dhcp_allow_foreign INTEGER NOT NULL DEFAULT 0
```

and append a fifth migration entry:

```go
	`ALTER TABLE settings ADD COLUMN dhcp_allow_foreign INTEGER NOT NULL DEFAULT 0;`,
```

Extend the `SELECT`, `Scan`, `INSERT`, placeholders, `DO UPDATE SET`, and argument list in `internal/store/settings.go` exactly as Part 1 Task 2 Step 6 did for the other seven. **Do not add it to the `cv_settings_u` trigger.**

- [ ] **Step 4: Write the verdict function**

In `internal/app/dhcp.go`:

```go
// foreignVerdict decides whether a probe result blocks the start. The
// override exists for operators who genuinely run two servers - split
// scopes, a deliberate second scope on another VLAN - and is off by default
// because the failure it guards against takes down the whole network rather
// than one name.
func foreignVerdict(found []dhcpd.Foreign, allow bool) error {
	if len(found) == 0 || allow {
		return nil
	}
	return &ForeignServerError{Found: found}
}
```

In `build`, replace the inline refusal:

```go
	} else if err := foreignVerdict(foreign, v.DHCPAllowForeign); err != nil {
		return nil, err
	}
```

- [ ] **Step 5: Add the periodic probe**

Still in `internal/app/dhcp.go`, add to `dhcpRunner`:

```go
	// foreign is the last periodic probe result, for the UI banner. It never
	// stops the listener: pulling DHCP out from under a working network over
	// one transient answer is worse than the conflict it reacts to.
	foreign []dhcpd.Foreign
	// stopWatch cancels the periodic probe when the listener stops.
	stopWatch context.CancelFunc
```

```go
// foreignWatchEvery is how often a running server re-checks for company.
const foreignWatchEvery = 15 * time.Minute

// watchForeign warns about another DHCP server appearing after we started.
// It only ever logs and populates the banner.
func (d *dhcpRunner) watchForeign(ctx context.Context, iface string, self netip.Addr) {
	t := time.NewTicker(foreignWatchEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		found, err := dhcpd.DetectForeign(ctx, iface, 2*time.Second, self)
		if err != nil {
			d.logger.Warn("periodic dhcp conflict probe failed", "error", err)
			continue
		}
		d.mu.Lock()
		d.foreign = found
		d.mu.Unlock()
		for _, f := range found {
			d.logger.Warn("another DHCP server is answering on this network",
				"server", f.ServerID.String(), "offered", f.Offered.String())
		}
	}
}

// Foreign returns the last periodic probe result, for the UI banner.
func (d *dhcpRunner) Foreign() []dhcpd.Foreign {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]dhcpd.Foreign(nil), d.foreign...)
}
```

In `Reconcile`, after a successful start:

```go
	watchCtx, cancel := context.WithCancel(context.Background())
	d.stopWatch = cancel
	go d.watchForeign(watchCtx, v.DHCPInterface, info.Addr)
```

`info` is not in scope in `Reconcile` — have `build` return it alongside the server by changing its signature to `func (d *dhcpRunner) build(v store.Settings) (*dhcpd.Server, dhcpd.IfaceInfo, error)` and threading it through. In `stopLocked`, before clearing `d.running`:

```go
	if d.stopWatch != nil {
		d.stopWatch()
		d.stopWatch = nil
	}
	d.foreign = nil
```

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/app/ ./internal/store/ ./internal/settings/ -v`
Expected: PASS.

- [ ] **Step 7: Check for a data race**

Run: `go test ./internal/app/ -race -count=2`
Expected: PASS. `watchForeign` writes `d.foreign` from its own goroutine while the API reads it.

- [ ] **Step 8: Commit**

```bash
git add internal/store/ internal/app/dhcp.go internal/app/dhcp_test.go
git commit -m "feat(dhcp): add the foreign-server override and the periodic probe

The override is off by default and exists for operators who genuinely
run two servers. The periodic probe warns and populates a banner; it
never disables a running listener, because pulling DHCP out from under a
working network over one transient answer is worse than the conflict."
```

---

### Task 2: A MAC on a service

**Files:**
- Modify: `internal/store/model.go:19-33` (`Service`), `internal/store/store.go:36-43` (schema), `:487-500` (`putService`), `:543` (`Service` query), migrations; `internal/registry/validate.go`, `internal/registry/registry.go:63-98`
- Test: `internal/registry/validate_test.go`, `internal/registry/registry_test.go`, `internal/store/store_test.go`

**Interfaces:**
- Produces: `store.Service.MAC string`; `registry.ValidateMAC(s string) error`; `validateService` normalizes and rejects a duplicate MAC with `registry.Invalid("mac", "duplicate", ...)`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/registry/validate_test.go`:

```go
func TestValidateMAC(t *testing.T) {
	good := []string{
		"aa:bb:cc:dd:ee:ff",
		"AA:BB:CC:DD:EE:FF",
		"aa-bb-cc-dd-ee-ff",
		"", // a service without a reservation is the normal case
	}
	for _, s := range good {
		if err := ValidateMAC(s); err != nil {
			t.Fatalf("ValidateMAC(%q) = %v, want nil", s, err)
		}
	}
	bad := []string{
		"nonsense",
		"aa:bb:cc:dd:ee",
		"aa:bb:cc:dd:ee:ff:00:11", // an EUI-64, not an Ethernet MAC
		"zz:bb:cc:dd:ee:ff",
	}
	for _, s := range bad {
		if err := ValidateMAC(s); err == nil {
			t.Fatalf("ValidateMAC(%q) = nil, want an error", s)
		}
	}
}

func TestNormalizeMACForm(t *testing.T) {
	cases := map[string]string{
		"AA:BB:CC:DD:EE:FF": "aa:bb:cc:dd:ee:ff",
		"aa-bb-cc-dd-ee-ff": "aa:bb:cc:dd:ee:ff",
		"  aa:bb:cc:dd:ee:ff  ": "aa:bb:cc:dd:ee:ff",
		"": "",
	}
	for in, want := range cases {
		if got := NormalizeMAC(in); got != want {
			t.Fatalf("NormalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
}
```

Add to `internal/registry/registry_test.go`:

```go
func TestPutServiceNormalizesMAC(t *testing.T) {
	r := newTestRegistry(t) // the existing helper
	id, err := r.PutService(store.Service{
		Name:      "kypost",
		Addresses: []store.Address{{Address: "192.168.1.20"}},
		MAC:       "AA-BB-CC-DD-EE-FF",
	})
	if err != nil {
		t.Fatalf("PutService: %v", err)
	}
	got, err := r.Service(id)
	if err != nil {
		t.Fatalf("Service: %v", err)
	}
	if got.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("stored MAC = %q, want the normalized form", got.MAC)
	}
}

func TestPutServiceRejectsADuplicateMAC(t *testing.T) {
	r := newTestRegistry(t)
	if _, err := r.PutService(store.Service{
		Name: "one", Addresses: []store.Address{{Address: "192.168.1.20"}},
		MAC: "aa:bb:cc:dd:ee:ff",
	}); err != nil {
		t.Fatalf("first PutService: %v", err)
	}
	_, err := r.PutService(store.Service{
		Name: "two", Addresses: []store.Address{{Address: "192.168.1.21"}},
		MAC: "AA:BB:CC:DD:EE:FF", // same MAC, different spelling
	})
	if err == nil {
		t.Fatal("PutService accepted two services reserving one MAC")
	}
}

func TestPutServiceAllowsManyServicesWithNoMAC(t *testing.T) {
	r := newTestRegistry(t)
	for _, n := range []string{"one", "two", "three"} {
		if _, err := r.PutService(store.Service{
			Name: n, Addresses: []store.Address{{Address: "192.168.1.20"}},
		}); err != nil {
			t.Fatalf("PutService(%s): %v", n, err)
		}
	}
}

func TestPutServiceKeepsItsOwnMACOnUpdate(t *testing.T) {
	r := newTestRegistry(t)
	id, err := r.PutService(store.Service{
		Name: "one", Addresses: []store.Address{{Address: "192.168.1.20"}},
		MAC: "aa:bb:cc:dd:ee:ff",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Re-saving the same service must not trip the duplicate check against
	// itself.
	if _, err := r.PutService(store.Service{
		ID: id, Name: "one", Addresses: []store.Address{{Address: "192.168.1.99"}},
		MAC: "aa:bb:cc:dd:ee:ff",
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/registry/ -run MAC -v`
Expected: FAIL to compile with `undefined: ValidateMAC` and `unknown field MAC in struct literal`.

- [ ] **Step 3: Add the field and the column**

In `internal/store/model.go`, add to `Service`:

```go
	// MAC is an optional DHCP reservation. Empty is the normal case. The
	// address it reserves is derived, not stored: it is the service's unique
	// address inside the DHCP subnet.
	MAC string
```

In `internal/store/store.go`, add to the `services` schema before `created_at`:

```sql
  mac             TEXT NOT NULL DEFAULT '',
```

and append a migration entry:

```go
	`ALTER TABLE services ADD COLUMN mac TEXT NOT NULL DEFAULT '';`,
```

Reservations are service configuration and must replicate, so the existing `cv_services_i` and `cv_services_u` triggers are exactly right. Change nothing about them.

- [ ] **Step 4: Read and write the column**

In `internal/store/store.go`, extend the insert at line 490:

```go
		res, err := tx.Exec(
			`INSERT INTO services(name, check_url, check_insecure, proxy_address, route_via_proxy, mac) VALUES(?, ?, ?, ?, ?, ?)`,
			svc.Name, svc.CheckURL, svc.CheckInsecure, svc.ProxyAddress, svc.RouteViaProxy, svc.MAC)
```

Add `mac = ?` and `svc.MAC` to the `UPDATE services` branch immediately below it, and `mac` plus `&svc.MAC` to the `SELECT` and `Scan` at line 543.

- [ ] **Step 5: Add the validators**

In `internal/registry/validate.go`:

```go
// NormalizeMAC is the one form a MAC is stored and compared in: lowercase,
// colon-separated. It matches dhcpd's normalization of the MAC on the wire,
// so a reservation and a lease compare directly.
func NormalizeMAC(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	hw, err := net.ParseMAC(s)
	if err != nil {
		return strings.ToLower(s) // invalid; ValidateMAC reports it
	}
	return strings.ToLower(hw.String())
}

// ValidateMAC accepts an empty MAC - most services have no reservation - and
// otherwise requires a 6-byte Ethernet address. Longer forms parse as MACs
// but are not something a DHCPv4 client will present.
func ValidateMAC(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	hw, err := net.ParseMAC(s)
	if err != nil {
		return invalid("mac", "malformed", "%q is not a MAC address", s)
	}
	if len(hw) != 6 {
		return invalid("mac", "malformed", "%q is not a 6-byte Ethernet MAC address", s)
	}
	return nil
}
```

Add `"net"` to the imports.

- [ ] **Step 6: Enforce it in `validateService`**

In `internal/registry/registry.go`, inside `validateService` (line 63), after the existing name validation:

```go
	if err := ValidateMAC(svc.MAC); err != nil {
		return store.Service{}, err
	}
	svc.MAC = NormalizeMAC(svc.MAC)
	if svc.MAC != "" {
		others, err := r.s.Services()
		if err != nil {
			return store.Service{}, err
		}
		for _, o := range others {
			if o.ID != svc.ID && o.MAC == svc.MAC {
				return store.Service{}, Invalid("mac", "duplicate",
					"%s is already reserved by the service %q", svc.MAC, o.Name)
			}
		}
	}
```

The uniqueness check is a scan rather than a unique index because the empty string is the common value and a partial index over a nullable column would mean making the column nullable for one check. Service counts here are in the tens.

- [ ] **Step 7: Run the tests**

Run: `go test ./internal/registry/... ./internal/store/... -v`
Expected: PASS.

- [ ] **Step 8: Run the whole suite**

Run: `go test ./... -count=1`
Expected: PASS. `ReplaceAll` and the import/export paths touch `store.Service`; a failure here means one of them drops the new field.

- [ ] **Step 9: Commit**

```bash
git add internal/store/ internal/registry/
git commit -m "feat(registry): an optional MAC on a service

A reservation is a service, so naming a host and pinning its address are
one action on one object. MACs normalize to the same lowercase
colon-separated form dhcpd uses on the wire, so a reservation and a lease
compare directly. Reservations replicate; the cv_services triggers
already cover them."
```

---

### Task 3: Resolve services into reservations

**Files:**
- Create: `internal/dhcpd/reserve.go`
- Test: `internal/dhcpd/reserve_test.go`
- Modify: `internal/app/dhcp.go`

**Interfaces:**
- Produces:
  - `type ReservationProblem struct { Service, MAC, Reason string }`
  - `func Reservations(svcs []store.Service, subnet netip.Prefix) (map[string]netip.Addr, []ReservationProblem)`
- Consumes: `store.Service.MAC` (Task 2).

- [ ] **Step 1: Write the failing tests**

Create `internal/dhcpd/reserve_test.go`:

```go
package dhcpd

import (
	"net/netip"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

var testSubnet = netip.MustParsePrefix("192.168.1.0/24")

func TestReservationsResolvesTheUniqueInSubnetAddress(t *testing.T) {
	svcs := []store.Service{{
		Name: "kypost",
		MAC:  "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{
			{Address: "192.168.1.20"},
			{Address: "10.9.0.20", View: "vpn"}, // outside the DHCP subnet
		},
	}}
	got, problems := Reservations(svcs, testSubnet)
	if len(problems) != 0 {
		t.Fatalf("problems = %+v, want none", problems)
	}
	if want := netip.MustParseAddr("192.168.1.20"); got["aa:bb:cc:dd:ee:ff"] != want {
		t.Fatalf("reservation = %v, want %v", got["aa:bb:cc:dd:ee:ff"], want)
	}
}

func TestReservationsIgnoresServicesWithNoMAC(t *testing.T) {
	svcs := []store.Service{{
		Name:      "kypost",
		Addresses: []store.Address{{Address: "192.168.1.20"}},
	}}
	got, problems := Reservations(svcs, testSubnet)
	if len(got) != 0 || len(problems) != 0 {
		t.Fatalf("got %+v, problems %+v; a service with no MAC is not a reservation", got, problems)
	}
}

func TestReservationWithNoInSubnetAddressIsFlagged(t *testing.T) {
	svcs := []store.Service{{
		Name:      "offsite",
		MAC:       "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{{Address: "10.9.0.20"}},
	}}
	got, problems := Reservations(svcs, testSubnet)
	if len(got) != 0 {
		t.Fatalf("reservations = %+v, want none", got)
	}
	if len(problems) != 1 || problems[0].Service != "offsite" {
		t.Fatalf("problems = %+v, want one naming offsite", problems)
	}
	if problems[0].Reason == "" {
		t.Fatal("problem has no reason; the UI shows this to the operator verbatim")
	}
}

func TestReservationWithTwoInSubnetAddressesIsFlagged(t *testing.T) {
	svcs := []store.Service{{
		Name: "ambiguous",
		MAC:  "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{
			{Address: "192.168.1.20"},
			{Address: "192.168.1.21"},
		},
	}}
	got, problems := Reservations(svcs, testSubnet)
	if len(got) != 0 {
		t.Fatalf("reservations = %+v, want none: which of the two would it be?", got)
	}
	if len(problems) != 1 {
		t.Fatalf("problems = %+v, want one", problems)
	}
}

func TestReservationWithTheSameAddressInTwoViewsResolves(t *testing.T) {
	// One address, offered in two views, is still one address.
	svcs := []store.Service{{
		Name: "kypost",
		MAC:  "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{
			{Address: "192.168.1.20", View: "lan"},
			{Address: "192.168.1.20", View: "guest"},
		},
	}}
	got, problems := Reservations(svcs, testSubnet)
	if len(problems) != 0 {
		t.Fatalf("problems = %+v, want none: it is one address in two views", problems)
	}
	if want := netip.MustParseAddr("192.168.1.20"); got["aa:bb:cc:dd:ee:ff"] != want {
		t.Fatalf("reservation = %v, want %v", got["aa:bb:cc:dd:ee:ff"], want)
	}
}

func TestReservationsSkipsUnparseableAddresses(t *testing.T) {
	svcs := []store.Service{{
		Name: "kypost",
		MAC:  "aa:bb:cc:dd:ee:ff",
		Addresses: []store.Address{
			{Address: "not-an-address"},
			{Address: "192.168.1.20"},
		},
	}}
	got, problems := Reservations(svcs, testSubnet)
	if len(problems) != 0 {
		t.Fatalf("problems = %+v, want none", problems)
	}
	if want := netip.MustParseAddr("192.168.1.20"); got["aa:bb:cc:dd:ee:ff"] != want {
		t.Fatalf("reservation = %v, want %v", got["aa:bb:cc:dd:ee:ff"], want)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/dhcpd/ -run Reservation -v`
Expected: FAIL to compile with `undefined: Reservations`.

- [ ] **Step 3: Write the implementation**

Create `internal/dhcpd/reserve.go`:

```go
package dhcpd

import (
	"fmt"
	"net/netip"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// ReservationProblem is a reservation that cannot be resolved. Reason is
// shown to the operator verbatim, so it says what to do rather than what
// went wrong.
type ReservationProblem struct {
	Service string
	MAC     string
	Reason  string
}

// Reservations resolves services into MAC-to-address reservations.
//
// The reserved address is the service's unique address inside the DHCP
// subnet. That one rule is what lets per-view addresses exist without a
// second concept: a service answering differently on the LAN and over a VPN
// has exactly one LAN address, and that is the one DHCP can reserve. Zero or
// more than one, and the reservation is inactive and reported - never
// guessed at, because guessing here hands a device the wrong address.
func Reservations(svcs []store.Service, subnet netip.Prefix) (map[string]netip.Addr, []ReservationProblem) {
	out := map[string]netip.Addr{}
	var problems []ReservationProblem
	for _, svc := range svcs {
		if svc.MAC == "" {
			continue
		}
		seen := map[netip.Addr]bool{}
		for _, a := range svc.Addresses {
			addr, err := netip.ParseAddr(a.Address)
			if err != nil {
				continue // the registry validated these; a bad one is not this code's problem
			}
			if subnet.Contains(addr.Unmap()) {
				seen[addr.Unmap()] = true
			}
		}
		switch len(seen) {
		case 1:
			for addr := range seen {
				out[svc.MAC] = addr
			}
		case 0:
			problems = append(problems, ReservationProblem{
				Service: svc.Name, MAC: svc.MAC,
				Reason: fmt.Sprintf("no address inside the DHCP subnet %s; give it one to activate the reservation", subnet),
			})
		default:
			problems = append(problems, ReservationProblem{
				Service: svc.Name, MAC: svc.MAC,
				Reason: fmt.Sprintf("%d addresses inside the DHCP subnet %s; a reservation needs exactly one", len(seen), subnet),
			})
		}
	}
	return out, problems
}
```

- [ ] **Step 4: Feed the allocator**

In `internal/app/dhcp.go`, add to `dhcpRunner`:

```go
	// services reads the current service list. Reservations are derived from
	// it on every settings change and every registry write.
	services func() ([]store.Service, error)
	// problems is the last unresolved-reservation report, for the UI.
	problems []dhcpd.ReservationProblem
	// alloc is the running allocator, held so reservations can be refreshed
	// without rebuilding the listener.
	alloc *dhcpd.Allocator
	// subnet is the running server's subnet, for resolving reservations.
	subnet netip.Prefix
```

```go
// RefreshReservations re-derives reservations from the current services. It
// is called after every registry write, because renaming or re-addressing a
// service changes what its reservation resolves to.
func (d *dhcpRunner) RefreshReservations() {
	d.mu.Lock()
	alloc, subnet := d.alloc, d.subnet
	d.mu.Unlock()
	if alloc == nil {
		return
	}
	svcs, err := d.services()
	if err != nil {
		d.logger.Error("could not read services to refresh DHCP reservations", "error", err)
		return
	}
	res, problems := dhcpd.Reservations(svcs, subnet)
	alloc.SetReservations(res)
	d.mu.Lock()
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
```

In `build`, hold the allocator and subnet so `RefreshReservations` can reach them. Where `build` currently constructs the allocator inline:

```go
	alloc := dhcpd.NewAllocator(cfg, time.Now)
	d.alloc, d.subnet = alloc, info.Subnet
```

and pass `alloc` into `dhcpd.Options`. Call `d.RefreshReservations()` at the end of a successful `Reconcile`, and clear `d.alloc`, `d.subnet`, and `d.problems` in `stopLocked`.

- [ ] **Step 5: Hook the registry**

In `internal/app/serve.go`, the `registry.New` callback already rebuilds the zone snapshot on every write. Add the reservation refresh to it:

```go
	reg := registry.New(st, privateFQDN, func() error {
		// A service's address or MAC changing changes what its reservation
		// resolves to, so this is the same event.
		dhcpRun.RefreshReservations()
		if err := holder.Rebuild(); err != nil {
			logger.Error("snapshot rebuild failed, still serving the previous snapshot", "error", err)
			return err
		}
		return nil
	})
```

`dhcpRun` is constructed after `reg` in Part 1's ordering. Declare `var dhcpRun *dhcpRunner` above the `registry.New` call so the closure captures the variable, matching how `poller` is already handled at `internal/app/serve.go:81`. Guard the call with `if dhcpRun != nil`.

Set `services: st.Services` when constructing `dhcpRunner`.

- [ ] **Step 6: Run the tests**

Run: `go build ./... && go test ./internal/dhcpd/ ./internal/app/ -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/dhcpd/reserve.go internal/dhcpd/reserve_test.go internal/app/
git commit -m "feat(dhcpd): resolve services into DHCP reservations

The reserved address is the service's unique address inside the DHCP
subnet. Zero or two and the reservation is inactive and reported rather
than guessed at - guessing here hands a device the wrong address. That
one rule is what lets per-view addresses work without a second concept."
```

---

### Task 4: API for reservations, status, and the wizard

**Files:**
- Modify: `internal/adminapi/services.go`, `internal/adminapi/dhcp.go`, `internal/adminapi/api.go`, `internal/cli/settings.go`
- Test: `internal/adminapi/dhcp_test.go`, `internal/adminapi/services_test.go`

**Interfaces:**
- Produces:
  - `"mac"` on the service DTO.
  - `GET /api/dhcp/status` → `{"running","error","supported","reason","foreign":[{"server","offered"}],"problems":[{"service","mac","reason"}],"dual_stack":bool}`
  - `GET /api/dhcp/suggest?interface=<name>` → `{"interface","subnet","range_start","range_end","gateway","lease_seconds","dual_stack"}`

- [ ] **Step 1: Write the failing tests**

Add to `internal/adminapi/dhcp_test.go`:

```go
func TestDHCPSuggestFillsInTheForm(t *testing.T) {
	h, tok := newTestAPI(t)
	// Loopback is never a qualifying DHCP interface, so this asserts the
	// refusal path rather than depending on the CI host's interfaces.
	req := httptest.NewRequest(http.MethodGet, "/api/dhcp/suggest?interface=lo", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an interface that cannot serve DHCP", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "loopback") {
		t.Fatalf("body %q does not say why; the wizard shows this verbatim", rec.Body.String())
	}
}

func TestDHCPSuggestRejectsAnUnknownInterface(t *testing.T) {
	h, tok := newTestAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/api/dhcp/suggest?interface=definitely-not-real0", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestDHCPStatusReportsProblemsAndForeignServers(t *testing.T) {
	h, tok := newTestAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/api/dhcp/status", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Running  bool `json:"running"`
		Problems []struct {
			Service string `json:"service"`
		} `json:"problems"`
		Foreign []struct {
			Server string `json:"server"`
		} `json:"foreign"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Running {
		t.Fatal("running = true with DHCP disabled")
	}
	// Both must be present and empty rather than null, so the template can
	// range over them without a nil check.
	if body.Problems == nil || body.Foreign == nil {
		t.Fatalf("problems=%v foreign=%v; both must serialize as [] not null", body.Problems, body.Foreign)
	}
}
```

Add to `internal/adminapi/services_test.go`:

```go
func TestServiceJSONCarriesMAC(t *testing.T) {
	h, tok := newTestAPI(t)
	body := `{"name":"kypost","addresses":[{"address":"192.168.1.20"}],"mac":"AA:BB:CC:DD:EE:FF"}`
	req := httptest.NewRequest(http.MethodPost, "/api/services", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}

	get := httptest.NewRequest(http.MethodGet, "/api/services", nil)
	get.Header.Set("Authorization", "Bearer "+tok)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, get)
	if !strings.Contains(rec2.Body.String(), `"mac":"aa:bb:cc:dd:ee:ff"`) {
		t.Fatalf("services JSON = %s, want the normalized MAC", rec2.Body.String())
	}
}
```

Match the route paths and status codes this package actually uses — read `internal/adminapi/api.go` before pasting.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/adminapi/ -run 'DHCPSuggest|DHCPStatus|ServiceJSONCarriesMAC' -v`
Expected: FAIL — 404 on the two new routes, and no `mac` in the service JSON.

- [ ] **Step 3: Add MAC to the service DTO**

In `internal/adminapi/services.go`, add `MAC string \`json:"mac"\`` to the service DTO and map it in both conversion directions, following the neighbouring fields exactly.

- [ ] **Step 4: Add the status and suggest handlers**

In `internal/adminapi/dhcp.go`:

```go
// DHCPStatusFull is everything the DHCP tab needs in one request: whether the
// listener is running, whether it could, what is standing in the way, and the
// caveats worth telling the operator about.
type DHCPStatusFull struct {
	Running   bool                 `json:"running"`
	Error     string               `json:"error,omitempty"`
	Supported bool                 `json:"supported"`
	Reason    string               `json:"reason,omitempty"`
	Foreign   []DHCPForeign        `json:"foreign"`
	Problems  []DHCPProblem        `json:"problems"`
	DualStack bool                 `json:"dual_stack"`
}

type DHCPForeign struct {
	Server  string `json:"server"`
	Offered string `json:"offered"`
}

type DHCPProblem struct {
	Service string `json:"service"`
	MAC     string `json:"mac"`
	Reason  string `json:"reason"`
}

func (a *API) dhcpStatus(w http.ResponseWriter, r *http.Request) {
	// Both slices are initialized, not nil: the template ranges over them,
	// and a JSON null there is a template error rather than an empty table.
	out := DHCPStatusFull{Foreign: []DHCPForeign{}, Problems: []DHCPProblem{}}
	if a.DHCP != nil {
		running, err := a.DHCP.Status()
		out.Running = running
		if err != nil {
			out.Error = err.Error()
		}
		for _, f := range a.DHCP.Foreign() {
			out.Foreign = append(out.Foreign, DHCPForeign{
				Server: f.ServerID.String(), Offered: f.Offered.String(),
			})
		}
		for _, p := range a.DHCP.Problems() {
			out.Problems = append(out.Problems, DHCPProblem{
				Service: p.Service, MAC: p.MAC, Reason: p.Reason,
			})
		}
	}
	v, err := a.Settings.Get()
	if err == nil && v.DHCPInterface != "" {
		if err := dhcpd.Qualifies(v.DHCPInterface); err != nil {
			out.Reason = err.Error()
		} else {
			out.Supported = true
			if info, err := dhcpd.Inspect(v.DHCPInterface); err == nil {
				out.DualStack = info.HasGlobalIPv6
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// DHCPSuggestion is the wizard's prefill. Every field is a proposal the
// operator confirms; nothing here is applied.
type DHCPSuggestion struct {
	Interface    string `json:"interface"`
	Subnet       string `json:"subnet"`
	RangeStart   string `json:"range_start"`
	RangeEnd     string `json:"range_end"`
	Gateway      string `json:"gateway"`
	LeaseSeconds int    `json:"lease_seconds"`
	DualStack    bool   `json:"dual_stack"`
}

func (a *API) dhcpSuggest(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("interface")
	if name == "" {
		writeError(w, http.StatusBadRequest, "interface is required")
		return
	}
	if err := dhcpd.Qualifies(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	info, err := dhcpd.Inspect(name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	start, end, err := dhcpd.SuggestRange(info.Subnet, info.Addr, info.Gateway)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// 24 hours is not arbitrary: clients renew at half the lease, so an
	// outage has roughly twelve hours before anything loses its address.
	writeJSON(w, http.StatusOK, DHCPSuggestion{
		Interface:    name,
		Subnet:       info.Subnet.String(),
		RangeStart:   start.String(),
		RangeEnd:     end.String(),
		Gateway:      info.Gateway.String(),
		LeaseSeconds: 86400,
		DualStack:    info.HasGlobalIPv6,
	})
}
```

Widen the `DHCP` interface field on `API` to what these need:

```go
	DHCP interface {
		Status() (bool, error)
		Foreign() []dhcpd.Foreign
		Problems() []dhcpd.ReservationProblem
	}
```

Register both routes beside the existing ones:

```go
	mux.HandleFunc("GET /api/dhcp/status", a.dhcpStatus)
	mux.HandleFunc("GET /api/dhcp/suggest", a.dhcpSuggest)
```

`writeError` is whatever this package's existing error helper is called — check `internal/adminapi/api.go` and use that name.

- [ ] **Step 5: Add the CLI keys**

In `internal/cli/settings.go`, add `dhcp.allow_foreign` to the settings key table. Add `--mac` to the `service add` and `service update` commands, following how `--check` and `--address` are already declared.

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/adminapi/... ./internal/cli/... -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/adminapi/ internal/cli/
git commit -m "feat(api,cli): DHCP status, the wizard prefill, and service MACs

Status answers in one request what the tab needs: running, could-it-run,
what is in the way, unresolved reservations, and whether the segment is
dual-stack. Foreign and problems serialize as [] rather than null so the
template can range over them."
```

---

### Task 5: The DHCP tab

**Files:**
- Create: `internal/web/dhcp.go`, `internal/web/templates/dhcp.html`
- Modify: `internal/web/pages.go`
- Test: `internal/web/dhcp_test.go`

**Interfaces:**
- Consumes: the API handlers from Task 4, or the same underlying components — follow whichever the existing pages do (check `internal/web/blacklists.go`).
- Produces: `GET /dhcp`, `POST /dhcp/settings`, `POST /dhcp/suggest`, `POST /dhcp/reserve`.

- [ ] **Step 1: Write the failing tests**

Create `internal/web/dhcp_test.go`, following `internal/web/blacklists_test.go` for the harness:

```go
package web

import (
	"strings"
	"testing"
)

func TestDHCPPageRendersWhenOff(t *testing.T) {
	h, c := newTestWeb(t) // the existing helper
	body := page(t, h, "/dhcp", c)
	if !strings.Contains(body, "DHCP") {
		t.Fatalf("page does not mention DHCP: %s", body)
	}
	if !strings.Contains(strings.ToLower(body), "not running") {
		t.Fatalf("page does not say the server is off: %s", body)
	}
}

func TestDHCPPageShowsTheUnsupportedReason(t *testing.T) {
	h, c := newTestWeb(t)
	setSetting(t, h, c, "dhcp_interface", "lo") // never qualifies
	body := page(t, h, "/dhcp", c)
	if !strings.Contains(strings.ToLower(body), "loopback") {
		t.Fatalf("page does not explain why DHCP cannot run here: %s", body)
	}
}

func TestDHCPPageShowsTheDualStackNote(t *testing.T) {
	h, c := newTestWebWithDHCP(t, dhcpView{Running: true, DualStack: true})
	body := page(t, h, "/dhcp", c)
	if !strings.Contains(body, "IPv6") {
		t.Fatalf("no dual-stack note on a dual-stack segment: %s", body)
	}
	if !strings.Contains(strings.ToLower(body), "router") {
		t.Fatalf("the dual-stack note does not name the workaround: %s", body)
	}
}

func TestDHCPPageHidesTheDualStackNoteOnIPv4Only(t *testing.T) {
	h, c := newTestWebWithDHCP(t, dhcpView{Running: true, DualStack: false})
	body := page(t, h, "/dhcp", c)
	if strings.Contains(body, "IPv6") {
		t.Fatalf("dual-stack note shown on an IPv4-only segment: %s", body)
	}
}

func TestDHCPPageListsUnresolvedReservations(t *testing.T) {
	h, c := newTestWebWithDHCP(t, dhcpView{
		Running: true,
		Problems: []problemView{{
			Service: "ambiguous", MAC: "aa:bb:cc:dd:ee:ff",
			Reason: "2 addresses inside the DHCP subnet",
		}},
	})
	body := page(t, h, "/dhcp", c)
	if !strings.Contains(body, "ambiguous") {
		t.Fatalf("unresolved reservation not shown: %s", body)
	}
}

func TestDHCPPageWarnsAboutAnotherServer(t *testing.T) {
	h, c := newTestWebWithDHCP(t, dhcpView{
		Running: true,
		Foreign: []foreignView{{Server: "192.168.1.1", Offered: "192.168.1.64"}},
	})
	body := page(t, h, "/dhcp", c)
	if !strings.Contains(body, "192.168.1.1") {
		t.Fatalf("the other DHCP server is not named: %s", body)
	}
}

func TestDHCPPageRequiresAuth(t *testing.T) {
	h, _ := newTestWeb(t)
	if code := statusOf(t, h, "/dhcp", nil); code == 200 {
		t.Fatal("the DHCP page rendered without a session; lease data names devices")
	}
}
```

`newTestWebWithDHCP`, `dhcpView`, `problemView`, and `foreignView` are yours to define in Step 3 — name the view types whatever fits the shape `internal/web/blacklists.go` already uses for its page data. `page`, `statusOf`, and `setSetting` are placeholders for this package's existing helpers; read `blacklists_test.go` and reuse them.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/web/ -run DHCPPage -v`
Expected: FAIL — `/dhcp` 404s.

- [ ] **Step 3: Write the handler and view types**

Create `internal/web/dhcp.go`, following the structure of `internal/web/blacklists.go`. The page data:

```go
// dhcpView is everything the tab renders. It is assembled server-side in one
// pass so the template has no logic beyond ranging and truthiness.
type dhcpView struct {
	Enabled      bool
	Running      bool
	Supported    bool
	Reason       string // why DHCP cannot run here, shown verbatim
	Error        string // why the listener did not start
	Interface    string
	RangeStart   string
	RangeEnd     string
	Gateway      string
	LeaseSeconds int
	SecondaryDNS string
	AllowForeign bool
	DualStack    bool
	Foreign      []foreignView
	Problems     []problemView
	Leases       []leaseView
}

type foreignView struct{ Server, Offered string }

type problemView struct{ Service, MAC, Reason string }

type leaseView struct {
	MAC      string
	IP       string
	Hostname string
	Expires  string // already humanized
	Reserved bool   // a service already reserves this MAC
}
```

Handlers:

- `GET /dhcp` — assemble `dhcpView` and render.
- `POST /dhcp/suggest` — read the chosen interface, call `dhcpd.Qualifies` then `dhcpd.Inspect` and `dhcpd.SuggestRange`, and re-render the form pre-filled without saving. This is the wizard: the operator sees the proposal and confirms it.
- `POST /dhcp/settings` — write through the same settings service every other page uses, so validation and the live apply are shared. On a `settings.FieldError`, re-render with the field flagged, matching how `serversettings.go` already does it.
- `POST /dhcp/reserve` — take a MAC and an IP from the lease table and create or update a service, reusing the existing promote-to-service path in `internal/adminapi/api.go:815`. Do not write a second one.

Use `humanize.go`'s existing helper for the expiry column rather than formatting a time in the template.

- [ ] **Step 4: Write the template**

Create `internal/web/templates/dhcp.html`, following `blacklists.html` for block structure and CSS classes:

```html
{{define "content"}}
<h1>DHCP</h1>

{{if not .Supported}}
  <div class="notice notice-blocked">
    <p><strong>DHCP cannot run here.</strong> {{.Reason}}</p>
  </div>
{{end}}

{{if .Error}}
  <div class="notice notice-error">
    <p><strong>DHCP is enabled but did not start.</strong> {{.Error}}</p>
  </div>
{{end}}

{{if .Foreign}}
  <div class="notice notice-warn">
    <p><strong>Another DHCP server is answering on this network.</strong>
       Two servers on one segment hand out conflicting addresses.</p>
    <ul>
      {{range .Foreign}}<li>{{.Server}} — offering {{.Offered}}</li>{{end}}
    </ul>
  </div>
{{end}}

{{if and .Running .DualStack}}
  <div class="notice notice-info">
    <p><strong>This network also runs IPv6.</strong> Your router is probably
       advertising itself as a DNS server over IPv6, which clients often
       prefer — so some queries will bypass KyDNS and filtering will look
       intermittent. Turn off the IPv6 DNS advertisement on your router to
       stop that.</p>
  </div>
{{end}}

{{if .Problems}}
  <div class="notice notice-warn">
    <p><strong>Some reservations are inactive.</strong> A reservation needs
       exactly one service address inside the DHCP subnet.</p>
    <ul>
      {{range .Problems}}<li>{{.Service}} ({{.MAC}}) — {{.Reason}}</li>{{end}}
    </ul>
  </div>
{{end}}

<form method="post" action="/dhcp/settings" class="stack">
  {{template "csrf" .}}
  <label><input type="checkbox" name="enabled" value="1" {{if .Enabled}}checked{{end}}> Serve DHCP on this network</label>

  <label>Interface <input name="interface" value="{{.Interface}}" required></label>
  <button type="submit" formaction="/dhcp/suggest" class="secondary">Fill in from this interface</button>

  <label>Range start <input name="range_start" value="{{.RangeStart}}"></label>
  <label>Range end <input name="range_end" value="{{.RangeEnd}}"></label>
  <label>Gateway <input name="gateway" value="{{.Gateway}}"></label>
  <label>Lease seconds <input name="lease_seconds" type="number" value="{{.LeaseSeconds}}" min="300" max="604800"></label>
  <label>Second DNS server (optional) <input name="secondary_dns" value="{{.SecondaryDNS}}"></label>

  <label><input type="checkbox" name="allow_foreign" value="1" {{if .AllowForeign}}checked{{end}}>
    Start even if another DHCP server answers — only if you run two deliberately</label>

  <button type="submit">Save</button>
</form>

<h2>Leases</h2>
{{if not .Running}}
  <p class="muted">The DHCP server is not running, so there are no leases.</p>
{{else if not .Leases}}
  <p class="muted">No leases yet. Devices appear here as they ask for an address.</p>
{{else}}
<table>
  <thead><tr><th>MAC</th><th>Address</th><th>Name</th><th>Expires</th><th></th></tr></thead>
  <tbody>
  {{range .Leases}}
    <tr>
      <td>{{.MAC}}</td><td>{{.IP}}</td><td>{{.Hostname}}</td><td>{{.Expires}}</td>
      <td>
        {{if .Reserved}}<span class="muted">reserved</span>
        {{else}}
        <form method="post" action="/dhcp/reserve">
          {{template "csrf" .}}
          <input type="hidden" name="mac" value="{{.MAC}}">
          <input type="hidden" name="ip" value="{{.IP}}">
          <input type="hidden" name="hostname" value="{{.Hostname}}">
          <button type="submit">Reserve</button>
        </form>
        {{end}}
      </td>
    </tr>
  {{end}}
  </tbody>
</table>
{{end}}
{{end}}
```

The `csrf` template name and the notice class names must match what the other templates use — read `blacklists.html` and copy its conventions rather than these. In particular, the `{{template "csrf" .}}` inside the `range` receives a `leaseView`, not the page data; if the existing csrf template needs the page context, use `$` to reach it.

- [ ] **Step 5: Register the page**

In `internal/web/pages.go`, register `/dhcp` and the three POST routes behind the same auth middleware as `/blacklists`, and add DHCP to the navigation in `layout.html` beside Blacklists.

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/web/... -v`
Expected: PASS.

- [ ] **Step 7: Check the template parses in every state**

Run: `go test ./internal/web/ -run 'Render|Template' -v`
Expected: PASS. This package has render tests that walk every template; a `{{template "csrf" .}}` given the wrong dot fails here rather than in production.

- [ ] **Step 8: Commit**

```bash
git add internal/web/
git commit -m "feat(web): the DHCP tab

One page: the toggle, the six fields, a live lease table with promote-to-
reservation, and the notices - unsupported deployment, another server on
the segment, inactive reservations, and the dual-stack DNS leak. Every
notice is informational except the unsupported one; none of them block."
```

---

### Task 6: Documentation

**Files:**
- Modify: `README.md`, `DESGINE.md`, `SECURITY.md`, `docs/superpowers/specs/2026-08-13-kydns-settings-in-the-ui-design.md`

- [ ] **Step 1: Update the README's feature lists**

In "What works today", replace the existing DHCP line:

```markdown
- A built-in DHCP server, off by default: one interface, one range,
  reservations that are services, and a setup wizard that fills the form in
  from the interface you pick. It advertises KyDNS as the DNS server, which
  is the point — plenty of routers will not let you change that. It refuses
  to start if another DHCP server is already answering, and it needs a
  native install or Docker with `network_mode: host`, because DHCP has to
  hear broadcasts. DHCP lease discovery from a dnsmasq lease file still
  works for anyone who already runs their own.
```

In "Not yet", add:

```markdown
- **IPv6 DNS advertisement.** On a dual-stack network your router advertises
  itself as a DNS server over IPv6, and clients often prefer it — so some
  queries bypass KyDNS even with its DHCP server running. Turning off the
  router's IPv6 DNS advertisement fixes it. Doing it properly means KyDNS
  sending router advertisements itself, which it does not.
```

- [ ] **Step 2: Correct the restart-required list**

The README currently says `dhcp_lease_file` cannot change in a running process. Part 1 Task 1 made that untrue. Find the sentence near `README.md:153` and cut `dhcp_lease_file` from it, leaving `private_domain` as the only restart-required key.

- [ ] **Step 3: Update the settings spec**

In `docs/superpowers/specs/2026-08-13-kydns-settings-in-the-ui-design.md`, move `discovery.dhcp_lease_file` from "Requires a restart, and says so" into the applied-live list, and add a line recording why:

```markdown
`discovery.dhcp_lease_file` moved to applied-live when the built-in DHCP
server landed: the poller's source became swappable, which is what both
features needed.
```

- [ ] **Step 4: Update the design document**

In `DESGINE.md`, add `internal/dhcpd` to the "System shape" list:

```markdown
8. **DHCP server** (`internal/dhcpd`) — an optional DHCPv4 server on one
   interface. It implements the same lease-source interface as lease-file
   discovery, so the addresses it hands out reach DNS by the path that
   already existed. Node-local and primary-only: a replica never serves it.
```

Correct the count in the sentence above the list — it says "seven logical parts".

- [ ] **Step 5: Update SECURITY.md**

Under the existing note about discovery sources:

```markdown
- With the built-in DHCP server enabled, KyDNS parses packets from any
  device on the segment rather than reading a lease file. Malformed packets
  are counted and dropped. The lease table is bounded by the size of the
  configured range. Packet contents are not logged at default verbosity,
  because MACs and hostnames identify people's devices. Hostnames from
  option 12 are chosen by the client, so they are reduced to a single
  validated DNS label and can never shadow a service, an alias, or a manual
  record.
```

- [ ] **Step 6: Verify every claim**

Run: `go test ./... -count=1 && go vet ./...`
Expected: PASS, no vet output.

Then re-read each documentation change against the code as merged. Specifically confirm: `dhcp_lease_file` really does apply live (Part 1 Task 1), the DHCP tab really does show the dual-stack note (Task 5), and a replica really does refuse to serve DHCP (Part 1 Task 10, `dhcpWanted`). A documentation claim that is not true of the code is worse than no documentation.

- [ ] **Step 7: Commit**

```bash
git add README.md DESGINE.md SECURITY.md docs/superpowers/specs/
git commit -m "docs: the built-in DHCP server

Also corrects the restart-required list: dhcp_lease_file now applies
live, because the poller's source became swappable when DHCP landed."
```

---

## Self-Review

**Spec coverage.** Reservations as a MAC on a service, with the unique-in-subnet rule (Tasks 2, 3). The setup wizard, pre-filling from the interface (Tasks 4, 5). The DHCP tab with the lease table and `Reserve` (Task 5). The override for a foreign server and the 15-minute periodic probe that warns and never disables (Task 1). The dual-stack note, shown where an operator sees it and never blocking (Tasks 4, 5). Documentation, including the two corrections Part 1 made necessary (Task 6).

Everything the spec asks for is now covered across the two plans. Part 1's self-review listed the foreign-server override as the one place the implementation was stricter than the spec; Task 1 closes it.

**Type consistency.** `dhcpd.Foreign` and `dhcpd.ReservationProblem` are the internal types; `adminapi.DHCPForeign` and `adminapi.DHCPProblem` are their JSON shapes; `web.foreignView` and `web.problemView` are their template shapes. `Reservations` takes `[]store.Service` and returns `map[string]netip.Addr` keyed by the normalized MAC, which is what `Allocator.SetReservations` from Part 1 Task 5 accepts. `registry.NormalizeMAC` and `dhcpd.normalizeMAC` must produce identical output for any MAC a client can send — that is the assumption reservations rest on, and `TestPutServiceNormalizesMAC` plus Part 1's `TestSanitizeHostname` are the closest things to a check. If either normalizer changes, both change.

**Known scope note.** `dhcpd.normalizeMAC` is unexported and `registry.NormalizeMAC` is exported, so the shared assumption between them is not enforced by the compiler. Making one call the other would mean `registry` importing `dhcpd` or the reverse, and neither dependency is one this codebase wants. The comment on each names the other; that is the whole guard, and it is deliberately weak because the alternative is worse coupling.
