# Built-in DHCPv4 Server — Part 1: engine and operation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A working, operable DHCPv4 server on one interface — leases, allocation, conflict probing, rogue-server refusal, live enable/disable — driven from settings, the JSON API, and the CLI.

**Architecture:** A new `internal/dhcpd` package implements the existing `discovery/dhcp.Source` interface, so leases reach DNS through the path that already exists (`Poller` → `zone.Input.Leases`). `discovery.Poller` gains a swappable source, which is what lets DHCP be turned on without a restart and which retires the same restriction on `dhcp_lease_file`. Allocation is a pure, clock-injected unit with no I/O; sockets live only in the server and probe files.

**Tech Stack:** Go 1.26.5, `github.com/insomniacslk/dhcp/dhcpv4` and `.../dhcpv4/server4`, modernc SQLite, `net/netip`.

**Spec:** `docs/superpowers/specs/2026-08-19-kydns-builtin-dhcp-design.md`

## Global Constraints

Every task's requirements implicitly include these. Values are copied verbatim from the spec.

- **IPv4 only.** No DHCPv6, no router advertisements, no relay/`giaddr`, no option 82, no vendor classes, no per-host options, no PXE (`next-server`/`filename`), no BOOTP.
- **One scope, one interface.**
- **Off by default.** `dhcp.enabled` defaults to `false`.
- **DHCP settings are node-local and must never replicate.** Concretely: do not add any `dhcp_*` column to the `cv_settings_u` trigger's `WHEN` clause in `internal/store/store.go`. Do not create any `cv_` trigger on the lease table.
- **Deployment:** native install or Docker `network_mode: host` only. An interface qualifies when it exists, is up, is not loopback, has an IPv4 address with a prefix, and `/sys/class/net/<iface>/uevent` does not report `DEVTYPE=veth`.
- **Sockets:** UDP `0.0.0.0:67` with `SO_BINDTODEVICE`; replies are broadcast. No raw sockets, so the only capability needed is `CAP_NET_BIND_SERVICE`.
- **Lease time** clamped to 300–604800 seconds, default 86400.
- **Built-in DHCP and `dhcp_lease_file` are mutually exclusive.**
- **Conflict probe budget:** 100 ms shared across ARP and ICMP. **Quarantine:** 10 minutes, in memory.
- **Rogue probe:** 2 s wait; refuses to enable on a positive result unless overridden; the periodic probe (15 min) warns and never disables.
- Tests must not open a real DHCP socket. Every packet test runs the handler against a fake `net.PacketConn`.
- Commit at the end of every task.

---

## File Structure

**Created**

| File | Responsibility |
|---|---|
| `internal/dhcpd/iface.go` | Inspect a network interface: qualification, subnet, host address, default route. No DHCP knowledge. |
| `internal/dhcpd/alloc.go` | Pure address allocation: reservations, renewals, requested-IP, lowest-free, quarantine. No I/O, injected clock. |
| `internal/dhcpd/probe.go` | Is this address in use? ARP table read plus ICMP echo, shared 100 ms budget. |
| `internal/dhcpd/rogue.go` | Is another DHCP server on this segment? Sends a DISCOVER, collects foreign OFFERs. |
| `internal/dhcpd/server.go` | Packet handling and lifecycle. Implements `discovery/dhcp.Source`. |
| `internal/store/dhcplease.go` | Lease persistence. |

**Modified**

| File | Change |
|---|---|
| `internal/discovery/poller.go` | `SetSource`, nil-source tolerance, locked source access. |
| `internal/store/store.go` | `dhcp_*` settings columns and the `dhcp_leases` table, in both the base schema and a new migration. |
| `internal/store/model.go` | `Settings` DHCP fields, `DHCPLease` type. |
| `internal/store/settings.go` | Read and write the new columns. |
| `internal/settings/validate.go` | DHCP validation rules. |
| `internal/app/serve.go` | Always construct and run the poller; construct the DHCP server; expose it to the API. |
| `internal/app/apply.go` | Start, stop, and reconfigure the listener on a settings change. |
| `internal/adminapi/settings.go` | DHCP settings fields and a lease listing. |
| `internal/cli/settings.go` | The same, from the CLI. |
| `packaging/` | `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the systemd unit. |

---

### Task 1: Swap the poller's source at runtime

`discovery.Poller` is constructed with its source and `internal/app/serve.go:146` only builds it when `boot.DHCPLeaseFile` is non-empty. That is the entire reason `dhcp_lease_file` requires a restart. Making the source swappable is a prerequisite for enabling DHCP live, and retires that restriction as a side effect.

**Files:**
- Modify: `internal/discovery/poller.go:19-30` (struct), `:100-125` (`Poll`)
- Test: `internal/discovery/poller_test.go`

**Interfaces:**
- Consumes: `dhcp.Source` (`internal/discovery/dhcp/source.go:20`) — `Leases(ctx) ([]Lease, error)`, `Name() string`
- Produces: `func (p *Poller) SetSource(src dhcp.Source)`. `NewPoller` accepts a nil source. `Poll` with a nil source publishes an empty lease set.

- [ ] **Step 1: Write the failing tests**

Append to `internal/discovery/poller_test.go`. `fakeSource` may already exist in this file under another name — reuse it if so rather than adding a second.

```go
type namedSource struct {
	name   string
	leases []dhcp.Lease
}

func (s *namedSource) Leases(context.Context) ([]dhcp.Lease, error) { return s.leases, nil }
func (s *namedSource) Name() string                                 { return s.name }

func TestSetSourceSwapsWithoutRestart(t *testing.T) {
	a := &namedSource{name: "a", leases: []dhcp.Lease{{MAC: "aa", IP: "192.168.1.10", Hostname: "one"}}}
	b := &namedSource{name: "b", leases: []dhcp.Lease{{MAC: "bb", IP: "192.168.1.11", Hostname: "two"}}}

	p := NewPoller(a, time.Hour, func() {}, slog.New(slog.DiscardHandler))
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if got := p.Leases(); len(got) != 1 || got[0].Hostname != "one" {
		t.Fatalf("before swap = %+v, want the source-a lease", got)
	}

	p.SetSource(b)
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if got := p.Leases(); len(got) != 1 || got[0].Hostname != "two" {
		t.Fatalf("after swap = %+v, want the source-b lease", got)
	}
}

func TestNilSourceRetiresPublishedLeases(t *testing.T) {
	changed := 0
	p := NewPoller(
		&namedSource{name: "a", leases: []dhcp.Lease{{MAC: "aa", IP: "192.168.1.10", Hostname: "one"}}},
		time.Hour, func() { changed++ }, slog.New(slog.DiscardHandler))
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if changed != 1 {
		t.Fatalf("onChange called %d times after the first poll, want 1", changed)
	}

	p.SetSource(nil)
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("poll with no source: %v", err)
	}
	if got := p.Leases(); len(got) != 0 {
		t.Fatalf("leases after clearing the source = %+v, want none", got)
	}
	if changed != 2 {
		t.Fatalf("onChange called %d times, want 2: retiring every lease is a change", changed)
	}
}

func TestNewPollerToleratesNilSource(t *testing.T) {
	p := NewPoller(nil, time.Hour, func() {}, slog.New(slog.DiscardHandler))
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("poll with no source: %v", err)
	}
	if got := p.Leases(); len(got) != 0 {
		t.Fatalf("leases = %+v, want none", got)
	}
}
```


- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/discovery/ -run 'TestSetSource|TestNilSource|TestNewPollerTolerates' -v`
Expected: FAIL to compile with `p.SetSource undefined (type *Poller has no field or method SetSource)`.

- [ ] **Step 3: Move the source behind the config lock**

In `internal/discovery/poller.go`, the `src` field currently sits above `cfgMu` with the immutable fields. Move it under `cfgMu`'s protection by changing the struct comment and adding the accessors. Replace the field declaration block:

```go
type Poller struct {
	onChange func()
	logger   *slog.Logger

	cfgMu    sync.RWMutex
	src      dhcp.Source // nil when discovery is off
	interval time.Duration
	changed  chan struct{} // buffered 1; wakes a Run blocked on the old interval

	mu     sync.RWMutex
	leases []dhcp.Lease
	digest string
}
```

Add below `Interval()`:

```go
// SetSource swaps the lease source. A nil source turns discovery off; the
// next cycle publishes an empty set, which retires the names the old source
// put in the zone. The queued wake makes that cycle immediate rather than one
// interval away.
func (p *Poller) SetSource(src dhcp.Source) {
	p.cfgMu.Lock()
	p.src = src
	p.cfgMu.Unlock()
	select {
	case p.changed <- struct{}{}:
	default:
	}
}

func (p *Poller) source() dhcp.Source {
	p.cfgMu.RLock()
	defer p.cfgMu.RUnlock()
	return p.src
}

// sourceName is only for logs, so it names the absence rather than panicking.
func sourceName(src dhcp.Source) string {
	if src == nil {
		return "none"
	}
	return src.Name()
}
```

- [ ] **Step 4: Make `Poll` and `Run` tolerate a nil source**

Replace the body of `Poll` down to the `digest` call:

```go
func (p *Poller) Poll(ctx context.Context) error {
	src := p.source()
	var leases []dhcp.Lease
	if src != nil {
		var err error
		leases, err = src.Leases(ctx)
		if err != nil {
			return err
		}
	}
	d := digest(leases)
	...
```

In the same function, the two `p.src` references in the change-logging block become `src`, and the log line's source name becomes `sourceName(src)`. In `Run`, the warning log's `p.src.Name()` becomes `sourceName(p.source())`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/discovery/... -v`
Expected: PASS, including the pre-existing tests.

- [ ] **Step 6: Check for a data race**

Run: `go test ./internal/discovery/ -race -count=2`
Expected: PASS with no race report. `SetSource` writes what `Poll` reads, so this is the check that the lock is actually doing its job.

- [ ] **Step 7: Commit**

```bash
git add internal/discovery/poller.go internal/discovery/poller_test.go
git commit -m "feat(discovery): let the poller's lease source be swapped at runtime

The poller was constructed with its source and only built at all when a
lease file was configured, which is why dhcp_lease_file needed a restart.
A swappable source retires that, and is what will let the built-in DHCP
server be switched on without one."
```

---

### Task 2: Settings columns and the lease table

Two schema changes land together because they are one migration. Note what is deliberately absent: neither the new settings columns nor the lease table appears in any `cv_` trigger, which is what makes them node-local.

**Files:**
- Modify: `internal/store/model.go:79-98` (`Settings`), `internal/store/store.go:120-138` (base schema) and `:256` (`migrations`), `internal/store/settings.go`
- Test: `internal/store/settings_test.go`, `internal/store/store_test.go`

**Interfaces:**
- Produces: `store.Settings` gains `DHCPEnabled bool`, `DHCPInterface string`, `DHCPRangeStart string`, `DHCPRangeEnd string`, `DHCPGateway string`, `DHCPLeaseSeconds int`, `DHCPSecondaryDNS string`. New type `store.DHCPLease{MAC, IP, Hostname string; ExpiresAt, LastSeen int64}`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/store/settings_test.go`:

```go
func TestSettingsRoundTripsDHCPFields(t *testing.T) {
	s := openTestStore(t)
	v, _, err := s.Settings()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	v.DHCPEnabled = true
	v.DHCPInterface = "eth0"
	v.DHCPRangeStart = "192.168.1.128"
	v.DHCPRangeEnd = "192.168.1.254"
	v.DHCPGateway = "192.168.1.1"
	v.DHCPLeaseSeconds = 86400
	v.DHCPSecondaryDNS = "192.168.1.3"
	if err := s.PutSettings(v); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, ok, err := s.Settings()
	if err != nil || !ok {
		t.Fatalf("read back: %v ok=%v", err, ok)
	}
	if got != v {
		t.Fatalf("round trip = %+v, want %+v", got, v)
	}
}

func TestDHCPSettingsDoNotBumpConfigVersion(t *testing.T) {
	s := openTestStore(t)
	v, _, err := s.Settings()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := s.PutSettings(v); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	before, err := s.ConfigVersion()
	if err != nil {
		t.Fatalf("version: %v", err)
	}

	v.DHCPEnabled = true
	v.DHCPInterface = "eth0"
	if err := s.PutSettings(v); err != nil {
		t.Fatalf("write: %v", err)
	}

	after, err := s.ConfigVersion()
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if after != before {
		t.Fatalf("config version moved from %d to %d; DHCP settings are node-local and must not replicate", before, after)
	}
}
```

`openTestStore` is the existing helper in this package. If it is named differently, use whatever the neighbouring tests use — do not add a second one.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/store/ -run 'TestSettingsRoundTripsDHCP|TestDHCPSettingsDoNot' -v`
Expected: FAIL to compile with `v.DHCPEnabled undefined`.

- [ ] **Step 3: Add the fields to the model**

In `internal/store/model.go`, extend `Settings` after `HealthWorkers`:

```go
	// DHCP settings drive the built-in server. They are node-local: no cv_
	// trigger names them, so a replica never hears about them, and two DHCP
	// servers on one segment is exactly what that prevents.
	DHCPEnabled      bool
	DHCPInterface    string
	DHCPRangeStart   string
	DHCPRangeEnd     string
	DHCPGateway      string
	DHCPLeaseSeconds int
	DHCPSecondaryDNS string
```

And add the lease type at the end of the file:

```go
// DHCPLease is one address the built-in server has handed out. It is stored
// so a restart cannot re-issue an address that is still in use. Times are
// Unix seconds.
type DHCPLease struct {
	MAC       string
	IP        string
	Hostname  string
	ExpiresAt int64
	LastSeen  int64
}
```

- [ ] **Step 4: Add the columns to the base schema**

In `internal/store/store.go`, inside the `CREATE TABLE IF NOT EXISTS settings` block at line 120, add after `health_workers`:

```sql
  dhcp_enabled       INTEGER NOT NULL DEFAULT 0,
  dhcp_interface     TEXT NOT NULL DEFAULT '',
  dhcp_range_start   TEXT NOT NULL DEFAULT '',
  dhcp_range_end     TEXT NOT NULL DEFAULT '',
  dhcp_gateway       TEXT NOT NULL DEFAULT '',
  dhcp_lease_seconds INTEGER NOT NULL DEFAULT 86400,
  dhcp_secondary_dns TEXT NOT NULL DEFAULT ''
```

Remember the comma after `health_workers INTEGER NOT NULL`.

In the same schema string, after the `records` table and before the `cv_` triggers, add:

```sql
CREATE TABLE IF NOT EXISTS dhcp_leases (
  mac        TEXT PRIMARY KEY,
  ip         TEXT NOT NULL UNIQUE,
  hostname   TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL
);
```

Do not add a `cv_dhcp_leases_*` trigger. Leases never replicate.

- [ ] **Step 5: Add the migration**

Append a fourth entry to the `migrations` slice in `internal/store/store.go:256`:

```go
	`ALTER TABLE settings ADD COLUMN dhcp_enabled INTEGER NOT NULL DEFAULT 0;
	 ALTER TABLE settings ADD COLUMN dhcp_interface TEXT NOT NULL DEFAULT '';
	 ALTER TABLE settings ADD COLUMN dhcp_range_start TEXT NOT NULL DEFAULT '';
	 ALTER TABLE settings ADD COLUMN dhcp_range_end TEXT NOT NULL DEFAULT '';
	 ALTER TABLE settings ADD COLUMN dhcp_gateway TEXT NOT NULL DEFAULT '';
	 ALTER TABLE settings ADD COLUMN dhcp_lease_seconds INTEGER NOT NULL DEFAULT 86400;
	 ALTER TABLE settings ADD COLUMN dhcp_secondary_dns TEXT NOT NULL DEFAULT '';
	 CREATE TABLE IF NOT EXISTS dhcp_leases (
	   mac        TEXT PRIMARY KEY,
	   ip         TEXT NOT NULL UNIQUE,
	   hostname   TEXT NOT NULL,
	   expires_at INTEGER NOT NULL,
	   last_seen  INTEGER NOT NULL
	 );`,
```

- [ ] **Step 6: Read and write the new columns**

In `internal/store/settings.go`, extend the `SELECT` in `Settings()` with `dhcp_enabled, dhcp_interface, dhcp_range_start, dhcp_range_end, dhcp_gateway, dhcp_lease_seconds, dhcp_secondary_dns` and the matching `Scan` targets:

```go
		&v.HealthInterval, &v.HealthTimeout, &v.HealthWorkers,
		&v.DHCPEnabled, &v.DHCPInterface, &v.DHCPRangeStart, &v.DHCPRangeEnd,
		&v.DHCPGateway, &v.DHCPLeaseSeconds, &v.DHCPSecondaryDNS)
```

In `putSettings`, add the seven columns to the `INSERT` list, seven more `?` placeholders, seven `excluded.` assignments in the `DO UPDATE SET` clause, and the seven values in order at the end of the argument list.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./internal/store/... -v`
Expected: PASS. `TestDHCPSettingsDoNotBumpConfigVersion` passing is the proof that the trigger's `WHEN` clause was left alone.

- [ ] **Step 8: Verify the migration runs on an existing database**

The store tests open fresh databases, which take the base schema and skip migrations. Confirm the upgrade path separately:

Run: `go test ./internal/store/ -run 'Migrat|Upgrade' -v`
Expected: PASS. If this package has no existing migration test, add one that opens a store, closes it, sets `PRAGMA user_version = 3`, reopens, and asserts `Settings()` succeeds — the failure this guards against is an `ALTER` running against a column that already exists.

- [ ] **Step 9: Commit**

```bash
git add internal/store/
git commit -m "feat(store): add DHCP settings columns and the lease table

Both are node-local by construction: no cv_ trigger names them, so a
replica never hears about either. A test asserts the config version does
not move when a DHCP setting changes."
```

---

### Task 3: Lease persistence

**Files:**
- Create: `internal/store/dhcplease.go`
- Test: `internal/store/dhcplease_test.go`

**Interfaces:**
- Consumes: `store.DHCPLease` from Task 2.
- Produces: `func (s *Store) DHCPLeases() ([]DHCPLease, error)`, `func (s *Store) PutDHCPLease(l DHCPLease) error`, `func (s *Store) DeleteDHCPLease(mac string) error`, `func (s *Store) DeleteExpiredDHCPLeases(now int64) (int, error)`.

- [ ] **Step 1: Write the failing tests**

Create `internal/store/dhcplease_test.go`:

```go
package store

import "testing"

func TestDHCPLeaseRoundTrip(t *testing.T) {
	s := openTestStore(t)
	l := DHCPLease{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.130", Hostname: "laptop", ExpiresAt: 2000, LastSeen: 1000}
	if err := s.PutDHCPLease(l); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.DHCPLeases()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0] != l {
		t.Fatalf("leases = %+v, want exactly %+v", got, l)
	}
}

func TestPutDHCPLeaseMovesAnAddressToANewMAC(t *testing.T) {
	s := openTestStore(t)
	old := DHCPLease{MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.1.130", Hostname: "old", ExpiresAt: 2000, LastSeen: 1000}
	if err := s.PutDHCPLease(old); err != nil {
		t.Fatalf("put old: %v", err)
	}
	// The IP column is UNIQUE. Re-issuing a released address to a different
	// client is normal, so this must succeed and evict the old row rather
	// than fail on the constraint.
	next := DHCPLease{MAC: "bb:bb:bb:bb:bb:bb", IP: "192.168.1.130", Hostname: "new", ExpiresAt: 3000, LastSeen: 2500}
	if err := s.PutDHCPLease(next); err != nil {
		t.Fatalf("put next: %v", err)
	}
	got, err := s.DHCPLeases()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0] != next {
		t.Fatalf("leases = %+v, want only %+v", got, next)
	}
}

func TestPutDHCPLeaseMovesAClientToANewAddress(t *testing.T) {
	s := openTestStore(t)
	mac := "aa:bb:cc:dd:ee:ff"
	if err := s.PutDHCPLease(DHCPLease{MAC: mac, IP: "192.168.1.130", Hostname: "laptop", ExpiresAt: 2000, LastSeen: 1000}); err != nil {
		t.Fatalf("put first: %v", err)
	}
	next := DHCPLease{MAC: mac, IP: "192.168.1.131", Hostname: "laptop", ExpiresAt: 3000, LastSeen: 2500}
	if err := s.PutDHCPLease(next); err != nil {
		t.Fatalf("put second: %v", err)
	}
	got, err := s.DHCPLeases()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0] != next {
		t.Fatalf("leases = %+v, want only %+v", got, next)
	}
}

func TestDeleteExpiredDHCPLeases(t *testing.T) {
	s := openTestStore(t)
	for _, l := range []DHCPLease{
		{MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.1.130", Hostname: "gone", ExpiresAt: 1000, LastSeen: 500},
		{MAC: "bb:bb:bb:bb:bb:bb", IP: "192.168.1.131", Hostname: "kept", ExpiresAt: 9000, LastSeen: 500},
	} {
		if err := s.PutDHCPLease(l); err != nil {
			t.Fatalf("put %s: %v", l.MAC, err)
		}
	}
	n, err := s.DeleteExpiredDHCPLeases(5000)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	got, err := s.DHCPLeases()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Hostname != "kept" {
		t.Fatalf("leases = %+v, want only the unexpired one", got)
	}
}

func TestDeleteDHCPLease(t *testing.T) {
	s := openTestStore(t)
	mac := "aa:bb:cc:dd:ee:ff"
	if err := s.PutDHCPLease(DHCPLease{MAC: mac, IP: "192.168.1.130", Hostname: "laptop", ExpiresAt: 2000, LastSeen: 1000}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := s.DeleteDHCPLease(mac); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, err := s.DHCPLeases()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("leases = %+v, want none", got)
	}
	// Releasing a lease that is already gone is normal: a client can send
	// RELEASE twice. It must not error.
	if err := s.DeleteDHCPLease(mac); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/store/ -run 'DHCPLease' -v`
Expected: FAIL to compile with `s.PutDHCPLease undefined`.

- [ ] **Step 3: Write the implementation**

Create `internal/store/dhcplease.go`:

```go
package store

// DHCP leases are node-local: they are not replicated and no cv_ trigger
// names this table. They are persisted only so a restart cannot re-issue an
// address that is still in use.

// DHCPLeases returns every stored lease, expired ones included. Pruning is
// the allocator's job, on the schedule that suits it.
func (s *Store) DHCPLeases() ([]DHCPLease, error) {
	rows, err := s.db.Query(
		`SELECT mac, ip, hostname, expires_at, last_seen FROM dhcp_leases ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DHCPLease
	for rows.Next() {
		var l DHCPLease
		if err := rows.Scan(&l.MAC, &l.IP, &l.Hostname, &l.ExpiresAt, &l.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// PutDHCPLease stores one lease. Both keys move: a client can be given a new
// address, and a released address can be re-issued to a different client. The
// two deletes clear whichever unique key the new row would collide with, so
// this is an upsert on either.
func (s *Store) PutDHCPLease(l DHCPLease) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM dhcp_leases WHERE ip = ? AND mac <> ?`, l.IP, l.MAC); err != nil {
		return err
	}
	if _, err := tx.Exec(`
INSERT INTO dhcp_leases (mac, ip, hostname, expires_at, last_seen)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(mac) DO UPDATE SET
  ip=excluded.ip, hostname=excluded.hostname,
  expires_at=excluded.expires_at, last_seen=excluded.last_seen`,
		l.MAC, l.IP, l.Hostname, l.ExpiresAt, l.LastSeen); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteDHCPLease drops one lease. Deleting one that is not there is not an
// error: a client may send RELEASE more than once.
func (s *Store) DeleteDHCPLease(mac string) error {
	_, err := s.db.Exec(`DELETE FROM dhcp_leases WHERE mac = ?`, mac)
	return err
}

// DeleteExpiredDHCPLeases prunes leases that expired at or before now, and
// returns how many went.
func (s *Store) DeleteExpiredDHCPLeases(now int64) (int, error) {
	res, err := s.db.Exec(`DELETE FROM dhcp_leases WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/store/ -run 'DHCPLease' -v`
Expected: PASS, all five.

- [ ] **Step 5: Commit**

```bash
git add internal/store/dhcplease.go internal/store/dhcplease_test.go
git commit -m "feat(store): persist DHCP leases

Both unique keys move in practice - a client gets a new address, an
address is re-issued to a new client - so the write clears whichever key
would collide before inserting."
```

---

### Task 4: Interface inspection

Everything the server needs to know about the host's network, with no DHCP knowledge in it. This is also where the deployment gate lives.

**Files:**
- Create: `internal/dhcpd/iface.go`
- Test: `internal/dhcpd/iface_test.go`

**Interfaces:**
- Produces:
  - `type IfaceInfo struct { Name string; Addr netip.Addr; Subnet netip.Prefix; Gateway netip.Addr; HasGlobalIPv6 bool }`
  - `func Inspect(name string) (IfaceInfo, error)`
  - `func Qualifies(name string) error` — nil when the interface can serve DHCP, otherwise an error whose message is shown to the operator verbatim.
  - `var ErrNotSupported = errors.New(...)` for the veth case.
  - `func defaultGateway() (netip.Addr, bool)`

- [ ] **Step 1: Write the failing tests**

Create `internal/dhcpd/iface_test.go`. The parsing units are tested directly; `Inspect` against a real interface is not, because a CI machine's interfaces are not ours to depend on.

```go
package dhcpd

import (
	"net/netip"
	"testing"
)

func TestIsVethReadsDevtype(t *testing.T) {
	cases := []struct {
		name   string
		uevent string
		want   bool
	}{
		{"docker bridge veth", "INTERFACE=eth0\nIFINDEX=12\nDEVTYPE=veth\n", true},
		{"physical nic", "INTERFACE=enp3s0\nIFINDEX=2\n", false},
		{"bridge", "INTERFACE=br0\nIFINDEX=3\nDEVTYPE=bridge\n", false},
		{"devtype as a substring of something else", "INTERFACE=x\nNOTDEVTYPE=veth\n", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ueventIsVeth(c.uevent); got != c.want {
				t.Fatalf("ueventIsVeth(%q) = %v, want %v", c.uevent, got, c.want)
			}
		})
	}
}

func TestParseDefaultGateway(t *testing.T) {
	// /proc/net/route, tab-separated, addresses little-endian hex.
	// 0100A8C0 is 192.168.1.1. Destination 00000000 with flag bit 0x2 (UG)
	// is the default route.
	const table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t0000FEA9\t00000000\t0001\t0\t0\t1000\t0000FFFF\t0\t0\t0\n" +
		"eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	got, ok := parseProcRoute(table)
	if !ok {
		t.Fatal("parseProcRoute found no default route")
	}
	if want := netip.MustParseAddr("192.168.1.1"); got != want {
		t.Fatalf("gateway = %v, want %v", got, want)
	}
}

func TestParseDefaultGatewayWithNoDefaultRoute(t *testing.T) {
	const table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t0000FEA9\t00000000\t0001\t0\t0\t1000\t0000FFFF\t0\t0\t0\n"
	if _, ok := parseProcRoute(table); ok {
		t.Fatal("parseProcRoute claimed a default route where there is none")
	}
}

func TestSuggestRangeTakesTheUpperHalf(t *testing.T) {
	cases := []struct {
		name             string
		subnet           string
		host, gw         string
		wantStart, wantEnd string
	}{
		{"typical /24", "192.168.1.0/24", "192.168.1.5", "192.168.1.1", "192.168.1.128", "192.168.1.254"},
		{"/25", "10.0.0.0/25", "10.0.0.2", "10.0.0.1", "10.0.0.64", "10.0.0.126"},
		{"host sits in the upper half", "192.168.1.0/24", "192.168.1.200", "192.168.1.1", "192.168.1.128", "192.168.1.254"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start, end, err := SuggestRange(
				netip.MustParsePrefix(c.subnet),
				netip.MustParseAddr(c.host),
				netip.MustParseAddr(c.gw))
			if err != nil {
				t.Fatalf("SuggestRange: %v", err)
			}
			if start.String() != c.wantStart || end.String() != c.wantEnd {
				t.Fatalf("range = %v-%v, want %v-%v", start, end, c.wantStart, c.wantEnd)
			}
		})
	}
}

func TestSuggestRangeRefusesATinySubnet(t *testing.T) {
	// A /30 has two usable addresses. There is no range to suggest.
	_, _, err := SuggestRange(
		netip.MustParsePrefix("192.168.1.0/30"),
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("192.168.1.2"))
	if err == nil {
		t.Fatal("SuggestRange accepted a /30; it has no room for a pool")
	}
}
```

Note the third `SuggestRange` case: the host being inside the suggested range is not something the suggestion works around, because the operator is shown the range and can move it. What the *allocator* must never do is hand out the host's own address, and that is Task 5's job, not this one.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/dhcpd/ -v`
Expected: FAIL — the package does not exist yet (`no Go files in .../internal/dhcpd`).

- [ ] **Step 3: Write the implementation**

Create `internal/dhcpd/iface.go`:

```go
// Package dhcpd is the built-in DHCPv4 server: one scope, one interface.
// It implements discovery/dhcp.Source, so the leases it hands out reach DNS
// through the path lease-file discovery already uses.
package dhcpd

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// ErrNotSupported is returned when the host cannot serve DHCP at all. Its
// message is shown to the operator, so it names the two supported
// deployments rather than the internal reason.
var ErrNotSupported = errors.New(
	"DHCP needs to hear broadcasts from clients, which this deployment cannot: " +
		"run KyDNS as a native package install, or in Docker with network_mode: host")

// IfaceInfo is everything the server and the setup wizard need to know about
// the interface DHCP will run on.
type IfaceInfo struct {
	Name          string
	Addr          netip.Addr    // our IPv4 address on this interface
	Subnet        netip.Prefix  // masked
	Gateway       netip.Addr    // the host's default route; zero if there is none
	HasGlobalIPv6 bool          // evidence the segment is dual-stack
}

// Inspect reads the interface. It does not decide whether DHCP may run;
// Qualifies does that.
func Inspect(name string) (IfaceInfo, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return IfaceInfo{}, fmt.Errorf("interface %q: %w", name, err)
	}
	info := IfaceInfo{Name: name}
	addrs, err := ifi.Addrs()
	if err != nil {
		return IfaceInfo{}, fmt.Errorf("interface %q addresses: %w", name, err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.Is4() && !info.Addr.IsValid() {
			ones, _ := n.Mask.Size()
			info.Addr = addr
			info.Subnet = netip.PrefixFrom(addr, ones).Masked()
		}
		if addr.Is6() && addr.IsGlobalUnicast() && !addr.IsPrivate() {
			info.HasGlobalIPv6 = true
		}
	}
	if !info.Addr.IsValid() {
		return IfaceInfo{}, fmt.Errorf("interface %q has no IPv4 address", name)
	}
	if gw, ok := defaultGateway(); ok {
		info.Gateway = gw
	}
	return info, nil
}

// Qualifies reports whether DHCP may run on this interface. A nil return is
// the only thing that lets the listener start.
func Qualifies(name string) error {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("interface %q: %w", name, err)
	}
	if ifi.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface %q is down", name)
	}
	if ifi.Flags&net.FlagLoopback != 0 {
		return fmt.Errorf("interface %q is the loopback", name)
	}
	if isVeth(name) {
		// Everything above passes inside a bridge-mode container. The socket
		// would bind, and no client would ever be heard.
		return ErrNotSupported
	}
	if _, err := Inspect(name); err != nil {
		return err
	}
	return nil
}

func isVeth(name string) bool {
	b, err := os.ReadFile("/sys/class/net/" + name + "/uevent")
	if err != nil {
		return false
	}
	return ueventIsVeth(string(b))
}

// ueventIsVeth is split out so it can be tested without a sysfs.
func ueventIsVeth(uevent string) bool {
	for _, line := range strings.Split(uevent, "\n") {
		if strings.TrimSpace(line) == "DEVTYPE=veth" {
			return true
		}
	}
	return false
}

func defaultGateway() (netip.Addr, bool) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return netip.Addr{}, false
	}
	return parseProcRoute(string(b))
}

// parseProcRoute finds the default route's gateway. Addresses in
// /proc/net/route are little-endian hex; the default route is the one whose
// destination is zero and whose flags carry RTF_GATEWAY (0x2).
func parseProcRoute(table string) (netip.Addr, bool) {
	for _, line := range strings.Split(table, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 4 || f[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x2 == 0 {
			continue
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		var be [4]byte
		binary.BigEndian.PutUint32(be[:], binary.LittleEndian.Uint32(raw))
		return netip.AddrFrom4(be), true
	}
	return netip.Addr{}, false
}

// SuggestRange proposes a pool: the upper half of the subnet, ending one
// below the broadcast address. The wizard shows this and the operator can
// change it, so it errs toward being obviously a suggestion rather than
// toward cleverness.
func SuggestRange(subnet netip.Prefix, host, gw netip.Addr) (start, end netip.Addr, err error) {
	if !subnet.Addr().Is4() {
		return start, end, errors.New("the DHCP range must be an IPv4 subnet")
	}
	bits := subnet.Bits()
	if bits > 29 {
		return start, end, fmt.Errorf("subnet %v is too small to hold a DHCP range", subnet)
	}
	base := subnet.Masked().Addr().As4()
	size := uint32(1) << uint(32-bits)
	network := binary.BigEndian.Uint32(base[:])

	startU := network + size/2
	endU := network + size - 2 // one below the broadcast address

	var sb, eb [4]byte
	binary.BigEndian.PutUint32(sb[:], startU)
	binary.BigEndian.PutUint32(eb[:], endU)
	return netip.AddrFrom4(sb), netip.AddrFrom4(eb), nil
}
```

`host` and `gw` are accepted but unused in the body: the upper half of a subnet never contains a conventionally-placed host or gateway, and the allocator excludes them regardless. Keep them in the signature — Part 2's wizard passes them, and a later refinement that does need them should not be a signature change. Add `_ = host; _ = gw` if the linter objects.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/dhcpd/ -v`
Expected: PASS, all five test functions.

- [ ] **Step 5: Commit**

```bash
git add internal/dhcpd/iface.go internal/dhcpd/iface_test.go
git commit -m "feat(dhcpd): inspect the interface and gate on deployment

The veth check is what catches bridge-mode Docker, where every other
check passes, the socket binds happily, and no client is ever heard."
```

---

### Task 5: The allocator

Pure logic, injected clock, no I/O and no sockets. This is where every allocation rule in the spec lives, so it gets the densest tests.

**Files:**
- Create: `internal/dhcpd/alloc.go`
- Test: `internal/dhcpd/alloc_test.go`

**Interfaces:**
- Consumes: `IfaceInfo` (Task 4) for the subnet and the host's own address.
- Produces:
  - `type Lease struct { MAC string; IP netip.Addr; Hostname string; Expires time.Time }`
  - `type Config struct { Subnet netip.Prefix; Start, End, Host, Gateway netip.Addr; LeaseTime time.Duration }`
  - `func NewAllocator(cfg Config, now func() time.Time) *Allocator`
  - `func (a *Allocator) Load(ls []Lease)`
  - `func (a *Allocator) SetReservations(r map[string]netip.Addr)`
  - `func (a *Allocator) Allocate(mac, hostname string, requested netip.Addr) (Lease, bool)`
  - `func (a *Allocator) Release(mac string)`
  - `func (a *Allocator) Decline(ip netip.Addr)`
  - `func (a *Allocator) Leases() []Lease`
  - `func (a *Allocator) Quarantine(ip netip.Addr)`
  - `func (a *Allocator) NameTaken(hostname, mac string) bool`

- [ ] **Step 1: Write the failing tests**

Create `internal/dhcpd/alloc_test.go`:

```go
package dhcpd

import (
	"net/netip"
	"testing"
	"time"
)

var epoch = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func testConfig() Config {
	return Config{
		Subnet:    netip.MustParsePrefix("192.168.1.0/24"),
		Start:     netip.MustParseAddr("192.168.1.10"),
		End:       netip.MustParseAddr("192.168.1.12"),
		Host:      netip.MustParseAddr("192.168.1.5"),
		Gateway:   netip.MustParseAddr("192.168.1.1"),
		LeaseTime: 24 * time.Hour,
	}
}

func newTestAllocator(t *testing.T) (*Allocator, *time.Time) {
	t.Helper()
	now := epoch
	return NewAllocator(testConfig(), func() time.Time { return now }), &now
}

func TestAllocateTakesTheLowestFreeAddress(t *testing.T) {
	a, _ := newTestAllocator(t)
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused the first client on an empty pool")
	}
	if want := netip.MustParseAddr("192.168.1.10"); l.IP != want {
		t.Fatalf("first address = %v, want %v", l.IP, want)
	}
	l2, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused the second client")
	}
	if want := netip.MustParseAddr("192.168.1.11"); l2.IP != want {
		t.Fatalf("second address = %v, want %v", l2.IP, want)
	}
}

func TestAllocateRenewsTheSameClient(t *testing.T) {
	a, now := newTestAllocator(t)
	first, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	*now = now.Add(time.Hour)
	second, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused a renewal")
	}
	if second.IP != first.IP {
		t.Fatalf("renewal moved the client from %v to %v", first.IP, second.IP)
	}
	if !second.Expires.After(first.Expires) {
		t.Fatalf("renewal did not extend the lease: %v then %v", first.Expires, second.Expires)
	}
}

func TestAllocateHonoursARequestedAddress(t *testing.T) {
	a, _ := newTestAllocator(t)
	want := netip.MustParseAddr("192.168.1.12")
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", want)
	if !ok {
		t.Fatal("Allocate refused a free requested address")
	}
	if l.IP != want {
		t.Fatalf("address = %v, want the requested %v", l.IP, want)
	}
}

func TestAllocateIgnoresARequestedAddressThatIsTaken(t *testing.T) {
	a, _ := newTestAllocator(t)
	taken, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	l, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", taken.IP)
	if !ok {
		t.Fatal("Allocate refused the second client entirely")
	}
	if l.IP == taken.IP {
		t.Fatalf("Allocate handed %v to a second client", l.IP)
	}
}

func TestAllocateIgnoresARequestedAddressOutsideTheRange(t *testing.T) {
	a, _ := newTestAllocator(t)
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.MustParseAddr("192.168.1.200"))
	if !ok {
		t.Fatal("Allocate refused the client")
	}
	if want := netip.MustParseAddr("192.168.1.10"); l.IP != want {
		t.Fatalf("address = %v, want %v from inside the range", l.IP, want)
	}
}

func TestReservationWinsOverEverything(t *testing.T) {
	a, _ := newTestAllocator(t)
	reserved := netip.MustParseAddr("192.168.1.50") // deliberately outside the range
	a.SetReservations(map[string]netip.Addr{"aa:aa:aa:aa:aa:aa": reserved})
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.MustParseAddr("192.168.1.11"))
	if !ok {
		t.Fatal("Allocate refused a reserved client")
	}
	if l.IP != reserved {
		t.Fatalf("address = %v, want the reserved %v", l.IP, reserved)
	}
}

func TestAReservedAddressIsNotHandedOutDynamically(t *testing.T) {
	a, _ := newTestAllocator(t)
	// Reserve an address that sits inside the dynamic range.
	a.SetReservations(map[string]netip.Addr{"cc:cc:cc:cc:cc:cc": netip.MustParseAddr("192.168.1.10")})
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused the client")
	}
	if want := netip.MustParseAddr("192.168.1.11"); l.IP != want {
		t.Fatalf("address = %v, want %v: .10 is reserved for another MAC", l.IP, want)
	}
}

func TestAllocateSkipsTheHostAndGateway(t *testing.T) {
	cfg := testConfig()
	cfg.Start = netip.MustParseAddr("192.168.1.1") // range now covers gateway and host
	cfg.End = netip.MustParseAddr("192.168.1.6")
	a := NewAllocator(cfg, func() time.Time { return epoch })
	l, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused the client")
	}
	if l.IP == cfg.Gateway || l.IP == cfg.Host {
		t.Fatalf("Allocate handed out %v, which is the gateway or our own address", l.IP)
	}
	if want := netip.MustParseAddr("192.168.1.2"); l.IP != want {
		t.Fatalf("address = %v, want %v", l.IP, want)
	}
}

func TestQuarantinedAddressIsSkippedThenReleased(t *testing.T) {
	a, now := newTestAllocator(t)
	a.Quarantine(netip.MustParseAddr("192.168.1.10"))
	l, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	if want := netip.MustParseAddr("192.168.1.11"); l.IP != want {
		t.Fatalf("address = %v, want %v while .10 is quarantined", l.IP, want)
	}

	*now = now.Add(quarantineFor + time.Second)
	a.Release("aa:aa:aa:aa:aa:aa")
	l2, _ := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{})
	if want := netip.MustParseAddr("192.168.1.10"); l2.IP != want {
		t.Fatalf("address = %v, want %v once the quarantine has expired", l2.IP, want)
	}
}

func TestDeclineQuarantines(t *testing.T) {
	a, _ := newTestAllocator(t)
	l, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	a.Decline(l.IP)
	l2, _ := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{})
	if l2.IP == l.IP {
		t.Fatalf("Allocate re-offered %v after it was declined", l.IP)
	}
}

func TestExpiredLeasesAreReusable(t *testing.T) {
	a, now := newTestAllocator(t)
	first, _ := a.Allocate("aa:aa:aa:aa:aa:aa", "one", netip.Addr{})
	*now = now.Add(25 * time.Hour)
	l, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused a client after every lease had expired")
	}
	if l.IP != first.IP {
		t.Fatalf("address = %v, want the expired %v to be reused", l.IP, first.IP)
	}
}

func TestExhaustionRefuses(t *testing.T) {
	a, _ := newTestAllocator(t)
	for _, mac := range []string{"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", "cc:cc:cc:cc:cc:cc"} {
		if _, ok := a.Allocate(mac, "x", netip.Addr{}); !ok {
			t.Fatalf("Allocate refused %s while the pool still had room", mac)
		}
	}
	if _, ok := a.Allocate("dd:dd:dd:dd:dd:dd", "x", netip.Addr{}); ok {
		t.Fatal("Allocate handed out a fourth address from a three-address pool")
	}
}

func TestLoadRestoresLeasesAcrossARestart(t *testing.T) {
	a, _ := newTestAllocator(t)
	held := netip.MustParseAddr("192.168.1.10")
	a.Load([]Lease{{
		MAC: "aa:aa:aa:aa:aa:aa", IP: held, Hostname: "one",
		Expires: epoch.Add(12 * time.Hour),
	}})
	l, ok := a.Allocate("bb:bb:bb:bb:bb:bb", "two", netip.Addr{})
	if !ok {
		t.Fatal("Allocate refused the new client")
	}
	if l.IP == held {
		t.Fatalf("Allocate re-issued %v, which a restored lease still holds", held)
	}
}

func TestNameTaken(t *testing.T) {
	a, _ := newTestAllocator(t)
	if _, ok := a.Allocate("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}); !ok {
		t.Fatal("Allocate refused the first client")
	}
	if !a.NameTaken("laptop", "bb:bb:bb:bb:bb:bb") {
		t.Fatal("NameTaken said laptop was free for a different MAC")
	}
	if a.NameTaken("laptop", "aa:aa:aa:aa:aa:aa") {
		t.Fatal("NameTaken said a client's own name was taken from it")
	}
	if a.NameTaken("desktop", "bb:bb:bb:bb:bb:bb") {
		t.Fatal("NameTaken said an unused name was taken")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/dhcpd/ -run 'TestAllocate|TestReservation|TestAReserved|TestQuarantined|TestDecline|TestExpired|TestExhaustion|TestLoad|TestNameTaken' -v`
Expected: FAIL to compile with `undefined: NewAllocator`.

- [ ] **Step 3: Write the implementation**

Create `internal/dhcpd/alloc.go`:

```go
package dhcpd

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// quarantineFor is how long an address that answered a probe, or that a
// client declined, is kept out of the pool. It is in memory only: losing it
// on restart costs one probe.
const quarantineFor = 10 * time.Minute

// Lease is one address the server has committed to a client.
type Lease struct {
	MAC      string
	IP       netip.Addr
	Hostname string
	Expires  time.Time
}

// Config is the pool. Host is our own address and Gateway the router's;
// both are excluded from allocation even when the range covers them, because
// an operator who typed a wide range did not mean to give away either.
type Config struct {
	Subnet    netip.Prefix
	Start     netip.Addr
	End       netip.Addr
	Host      netip.Addr
	Gateway   netip.Addr
	LeaseTime time.Duration
}

// Allocator owns address assignment. It holds no sockets and does no I/O, so
// every rule in it is testable against a fake clock.
type Allocator struct {
	now func() time.Time

	mu         sync.Mutex
	cfg        Config
	byMAC      map[string]Lease
	byIP       map[netip.Addr]string
	reserved   map[string]netip.Addr
	reservedIP map[netip.Addr]string
	quarantine map[netip.Addr]time.Time
}

func NewAllocator(cfg Config, now func() time.Time) *Allocator {
	if now == nil {
		now = time.Now
	}
	return &Allocator{
		now:        now,
		cfg:        cfg,
		byMAC:      map[string]Lease{},
		byIP:       map[netip.Addr]string{},
		reserved:   map[string]netip.Addr{},
		reservedIP: map[netip.Addr]string{},
		quarantine: map[netip.Addr]time.Time{},
	}
}

// Load restores persisted leases at startup. It replaces whatever is held,
// so it is a boot-time call, not an incremental one.
func (a *Allocator) Load(ls []Lease) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.byMAC, a.byIP = map[string]Lease{}, map[netip.Addr]string{}
	for _, l := range ls {
		a.byMAC[l.MAC] = l
		a.byIP[l.IP] = l.MAC
	}
}

// SetReservations replaces the MAC-to-address reservations. Part 2 feeds this
// from services; until then it is only ever set to an empty map.
func (a *Allocator) SetReservations(r map[string]netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reserved = map[string]netip.Addr{}
	a.reservedIP = map[netip.Addr]string{}
	for mac, ip := range r {
		a.reserved[mac] = ip
		a.reservedIP[ip] = mac
	}
}

// Reconfigure swaps the pool. Leases outside the new range are dropped: they
// name addresses this server no longer controls.
func (a *Allocator) Reconfigure(cfg Config) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg = cfg
	for ip, mac := range a.byIP {
		if !a.usable(ip) && a.reserved[mac] != ip {
			delete(a.byIP, ip)
			delete(a.byMAC, mac)
		}
	}
}

// Allocate returns the address this client should get, committing it. The
// bool is false only when the pool is exhausted.
func (a *Allocator) Allocate(mac, hostname string, requested netip.Addr) (Lease, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()

	commit := func(ip netip.Addr) (Lease, bool) {
		if held, ok := a.byIP[ip]; ok && held != mac {
			delete(a.byMAC, held)
		}
		if prev, ok := a.byMAC[mac]; ok && prev.IP != ip {
			delete(a.byIP, prev.IP)
		}
		l := Lease{MAC: mac, IP: ip, Hostname: hostname, Expires: now.Add(a.cfg.LeaseTime)}
		a.byMAC[mac] = l
		a.byIP[ip] = mac
		return l, true
	}

	// 1. A reservation always wins, in or out of the dynamic range.
	if ip, ok := a.reserved[mac]; ok {
		return commit(ip)
	}
	// 2. Renew what this client already holds, if it is still ours to give.
	if l, ok := a.byMAC[mac]; ok && a.usable(l.IP) && a.reservedIP[l.IP] == "" {
		return commit(l.IP)
	}
	// 3. Honour a requested address that is free.
	if requested.IsValid() && a.free(requested, mac, now) {
		return commit(requested)
	}
	// 4. Lowest free address in the range.
	for ip := a.cfg.Start; a.inRange(ip); ip = ip.Next() {
		if a.free(ip, mac, now) {
			return commit(ip)
		}
	}
	return Lease{}, false
}

// Release drops a client's lease, as a DHCPRELEASE does.
func (a *Allocator) Release(mac string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if l, ok := a.byMAC[mac]; ok {
		delete(a.byIP, l.IP)
		delete(a.byMAC, mac)
	}
}

// Decline quarantines an address a client rejected as already in use.
func (a *Allocator) Decline(ip netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if mac, ok := a.byIP[ip]; ok {
		delete(a.byMAC, mac)
		delete(a.byIP, ip)
	}
	a.quarantine[ip] = a.now().Add(quarantineFor)
}

// Quarantine keeps an address out of the pool, for a probe that found it in
// use by something we did not hand it to.
func (a *Allocator) Quarantine(ip netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.quarantine[ip] = a.now().Add(quarantineFor)
}

// Leases returns the unexpired leases, for the DNS zone and the UI.
func (a *Allocator) Leases() []Lease {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	out := make([]Lease, 0, len(a.byMAC))
	for _, l := range a.byMAC {
		if l.Expires.After(now) {
			out = append(out, l)
		}
	}
	return out
}

// NameTaken reports whether an unexpired lease held by a different client
// already claims this hostname. Option 12 is chosen by the client, so first
// claim wins for the life of the lease and the loser gets no name.
func (a *Allocator) NameTaken(hostname, mac string) bool {
	if hostname == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for _, l := range a.byMAC {
		if l.MAC != mac && l.Hostname == hostname && l.Expires.After(now) {
			return true
		}
	}
	return false
}

// free reports whether ip can be given to mac right now. Callers hold a.mu.
func (a *Allocator) free(ip netip.Addr, mac string, now time.Time) bool {
	if !a.usable(ip) {
		return false
	}
	if until, ok := a.quarantine[ip]; ok && until.After(now) {
		return false
	}
	if holder, ok := a.reservedIP[ip]; ok && holder != mac {
		return false
	}
	if holder, ok := a.byIP[ip]; ok && holder != mac {
		if l, ok := a.byMAC[holder]; ok && l.Expires.After(now) {
			return false
		}
	}
	return true
}

// usable reports whether ip is one this server may hand out at all.
func (a *Allocator) usable(ip netip.Addr) bool {
	return a.inRange(ip) && ip != a.cfg.Host && ip != a.cfg.Gateway
}

func (a *Allocator) inRange(ip netip.Addr) bool {
	if !ip.Is4() || !a.cfg.Start.Is4() || !a.cfg.End.Is4() {
		return false
	}
	return u32(ip) >= u32(a.cfg.Start) && u32(ip) <= u32(a.cfg.End)
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/dhcpd/ -v`
Expected: PASS, every allocator test plus Task 4's.

- [ ] **Step 5: Check for a data race**

Run: `go test ./internal/dhcpd/ -race -count=2`
Expected: PASS. The allocator is reached from the packet handler and the UI at once, so its mutex needs to be real.

- [ ] **Step 6: Commit**

```bash
git add internal/dhcpd/alloc.go internal/dhcpd/alloc_test.go
git commit -m "feat(dhcpd): address allocation

Reservation, then renewal, then requested-IP, then lowest-free, with
quarantine, exhaustion, and first-claim-wins hostname arbitration. No
sockets and an injected clock, so every rule is directly testable."
```

---

### Task 6: The conflict probe

**Files:**
- Create: `internal/dhcpd/probe.go`
- Test: `internal/dhcpd/probe_test.go`

**Interfaces:**
- Produces: `type Prober interface { InUse(ip netip.Addr) bool }`, `func NewProber(iface string, budget time.Duration) Prober`, `type nopProber struct{}` for tests and for the allocator paths that must not probe.

- [ ] **Step 1: Write the failing tests**

Create `internal/dhcpd/probe_test.go`. The ICMP path needs a network and privileges, so what is tested is the ARP-table parsing and the budget contract; the socket call itself is thin enough to read.

```go
package dhcpd

import (
	"net/netip"
	"testing"
	"time"
)

func TestParseARPTable(t *testing.T) {
	// /proc/net/arp. Flags 0x2 is ATF_COM, a complete entry; 0x0 is
	// incomplete and means the address did not answer.
	const table = "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n" +
		"192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        eth0\n"
	live := parseARPTable(table, "eth0")
	if !live[netip.MustParseAddr("192.168.1.1")] {
		t.Fatal("complete ARP entry was not treated as in use")
	}
	if live[netip.MustParseAddr("192.168.1.50")] {
		t.Fatal("incomplete ARP entry was treated as in use")
	}
}

func TestParseARPTableIgnoresOtherInterfaces(t *testing.T) {
	const table = "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n"
	if parseARPTable(table, "eth0")[netip.MustParseAddr("192.168.1.1")] {
		t.Fatal("an entry on another interface was counted")
	}
}

func TestNopProberNeverBlocks(t *testing.T) {
	start := time.Now()
	if (nopProber{}).InUse(netip.MustParseAddr("192.168.1.10")) {
		t.Fatal("nopProber reported an address in use")
	}
	if time.Since(start) > 10*time.Millisecond {
		t.Fatal("nopProber did I/O")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/dhcpd/ -run 'ARPTable|NopProber' -v`
Expected: FAIL to compile with `undefined: parseARPTable`.

- [ ] **Step 3: Write the implementation**

Create `internal/dhcpd/probe.go`:

```go
package dhcpd

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Prober answers one question: is this address already in use by something we
// did not give it to? A false negative costs a duplicate address, which the
// client then declines; a false positive costs one address for ten minutes.
// The budget is small because it sits in the path of every new OFFER.
type Prober interface {
	InUse(ip netip.Addr) bool
}

// nopProber is for renewals and reservations, which are not probed, and for
// tests.
type nopProber struct{}

func (nopProber) InUse(netip.Addr) bool { return false }

type prober struct {
	iface  string
	budget time.Duration
}

// NewProber returns a Prober that checks the kernel's ARP table first and
// then, if that says nothing, sends one ICMP echo. Both share budget.
func NewProber(iface string, budget time.Duration) Prober {
	if budget <= 0 {
		budget = 100 * time.Millisecond
	}
	return &prober{iface: iface, budget: budget}
}

func (p *prober) InUse(ip netip.Addr) bool {
	deadline := time.Now().Add(p.budget)
	if b, err := os.ReadFile("/proc/net/arp"); err == nil {
		if parseARPTable(string(b), p.iface)[ip] {
			return true
		}
	}
	return icmpAnswers(ip, time.Until(deadline))
}

// parseARPTable returns the addresses on iface with a complete (ATF_COM,
// 0x2) entry. A complete entry means something answered ARP for it recently.
func parseARPTable(table, iface string) map[netip.Addr]bool {
	live := map[netip.Addr]bool{}
	lines := strings.Split(table, "\n")
	if len(lines) > 0 {
		lines = lines[1:] // drop the header row
	}
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 6 || f[5] != iface {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if err != nil || flags&0x2 == 0 {
			continue
		}
		if addr, err := netip.ParseAddr(f[0]); err == nil {
			live[addr] = true
		}
	}
	return live
}

// icmpAnswers sends one echo request and waits for any reply. It needs an
// unprivileged ICMP socket, which Linux allows within
// net.ipv4.ping_group_range; where it is not permitted this returns false and
// the ARP check is the whole probe. That is a documented weaker check, not a
// silent one: the caller logs when the socket cannot be opened.
func icmpAnswers(ip netip.Addr, budget time.Duration) bool {
	if budget <= 0 {
		return false
	}
	c, err := net.DialTimeout("ip4:icmp", ip.String(), budget)
	if err != nil {
		return false
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(budget)); err != nil {
		return false
	}
	// Echo request: type 8, code 0, id and seq zero, no payload. The checksum
	// covers an otherwise-zero header, so it is a constant.
	msg := []byte{8, 0, 0xf7, 0xff, 0, 0, 0, 0}
	if _, err := c.Write(msg); err != nil {
		return false
	}
	buf := make([]byte, 64)
	_, err = c.Read(buf)
	return err == nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/dhcpd/ -run 'ARPTable|NopProber' -v`
Expected: PASS.

- [ ] **Step 5: Confirm the ICMP path degrades rather than fails**

Run: `go test ./internal/dhcpd/ -run 'ARPTable|NopProber' -count=1 -v` as an unprivileged user (which is how it already ran).
Expected: PASS. `icmpAnswers` returns false when the socket cannot be opened, so an unprivileged environment gets the ARP check alone and no error.

- [ ] **Step 6: Commit**

```bash
git add internal/dhcpd/probe.go internal/dhcpd/probe_test.go
git commit -m "feat(dhcpd): probe an address before offering it

ARP table first, then one ICMP echo, sharing a 100ms budget. Where the
ICMP socket is not permitted the ARP check stands alone and the caller
logs the downgrade rather than pretending to a check it did not make."
```

---

### Task 7: Packet handling

**Files:**
- Create: `internal/dhcpd/server.go`
- Test: `internal/dhcpd/server_test.go`
- Modify: `go.mod`, `go.sum`

**Interfaces:**
- Consumes: `Allocator`, `Prober`, `Config`, `IfaceInfo`.
- Produces:
  - `type Server struct { ... }` implementing `discovery/dhcp.Source`: `Leases(ctx) ([]dhcp.Lease, error)`, `Name() string`
  - `func New(opts Options) *Server`, `type Options struct { Iface IfaceInfo; Cfg Config; DNS []netip.Addr; Domain string; Alloc *Allocator; Prober Prober; Store LeaseStore; OnChange func(); Logger *slog.Logger }`
  - `type LeaseStore interface { DHCPLeases() ([]store.DHCPLease, error); PutDHCPLease(store.DHCPLease) error; DeleteDHCPLease(string) error; DeleteExpiredDHCPLeases(int64) (int, error) }`
  - `func (s *Server) handle(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4)` — the unit every packet test drives.
  - `func (s *Server) Start(ctx context.Context) error`, `func (s *Server) Stop() error`

- [ ] **Step 1: Add the dependency and confirm the API surface**

The exact names of the reply modifiers matter and must not be guessed.

```bash
go get github.com/insomniacslk/dhcp@latest
go doc github.com/insomniacslk/dhcp/dhcpv4 NewReplyFromRequest
go doc github.com/insomniacslk/dhcp/dhcpv4 | grep -E '^func (With|Opt)'
go doc github.com/insomniacslk/dhcp/dhcpv4/server4 NewServer
go doc github.com/insomniacslk/dhcp/dhcpv4/server4 Handler
```

Expected: `NewReplyFromRequest(request *DHCPv4, modifiers ...Modifier) (*DHCPv4, error)`; modifiers including `WithMessageType`, `WithYourIP`, `WithServerIP`, `WithOption`; option constructors including `OptSubnetMask`, `OptRouter`, `OptDNS`, `OptIPAddressLeaseTime`, `OptServerIdentifier`, `OptDomainName`; `server4.NewServer(ifname string, addr *net.UDPAddr, handler Handler, opt ...ServerOpt)`; `type Handler func(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4)`.

**If any name differs from the above, use what `go doc` reports and adjust the code in Step 3 to match.** Record the version you pinned in the commit message. Do not proceed on the assumption that this document is right and the module is wrong.

- [ ] **Step 2: Write the failing tests**

Create `internal/dhcpd/server_test.go`:

```go
package dhcpd

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// captureConn is the fake the handler writes replies into. No socket is
// opened anywhere in this file.
type captureConn struct {
	net.PacketConn
	mu   sync.Mutex
	sent [][]byte
}

func (c *captureConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, append([]byte(nil), b...))
	return len(b), nil
}

func (c *captureConn) replies(t *testing.T) []*dhcpv4.DHCPv4 {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*dhcpv4.DHCPv4
	for _, b := range c.sent {
		m, err := dhcpv4.FromBytes(b)
		if err != nil {
			t.Fatalf("reply is not a DHCP message: %v", err)
		}
		out = append(out, m)
	}
	return out
}

// memStore is an in-memory LeaseStore.
type memStore struct {
	mu sync.Mutex
	ls map[string]store.DHCPLease
}

func newMemStore() *memStore { return &memStore{ls: map[string]store.DHCPLease{}} }

func (m *memStore) DHCPLeases() ([]store.DHCPLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.DHCPLease, 0, len(m.ls))
	for _, l := range m.ls {
		out = append(out, l)
	}
	return out, nil
}

func (m *memStore) PutDHCPLease(l store.DHCPLease) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for mac, cur := range m.ls {
		if cur.IP == l.IP && mac != l.MAC {
			delete(m.ls, mac)
		}
	}
	m.ls[l.MAC] = l
	return nil
}

func (m *memStore) DeleteDHCPLease(mac string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ls, mac)
	return nil
}

func (m *memStore) DeleteExpiredDHCPLeases(now int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for mac, l := range m.ls {
		if l.ExpiresAt <= now {
			delete(m.ls, mac)
			n++
		}
	}
	return n, nil
}

func newTestServer(t *testing.T) (*Server, *memStore) {
	t.Helper()
	ms := newMemStore()
	cfg := testConfig()
	s := New(Options{
		Iface:  IfaceInfo{Name: "test0", Addr: cfg.Host, Subnet: cfg.Subnet, Gateway: cfg.Gateway},
		Cfg:    cfg,
		DNS:    []netip.Addr{cfg.Host},
		Domain: "home.arpa",
		Alloc:  NewAllocator(cfg, func() time.Time { return epoch }),
		Prober: nopProber{},
		Store:  ms,
		Logger: slog.New(slog.DiscardHandler),
	})
	return s, ms
}

func discover(mac string, hostname string) *dhcpv4.DHCPv4 {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	m, err := dhcpv4.NewDiscovery(hw)
	if err != nil {
		panic(err)
	}
	if hostname != "" {
		m.UpdateOption(dhcpv4.OptHostName(hostname))
	}
	return m
}

func request(mac, hostname string, requested netip.Addr) *dhcpv4.DHCPv4 {
	m := discover(mac, hostname)
	m.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))
	if requested.IsValid() {
		m.UpdateOption(dhcpv4.OptRequestedIPAddress(net.IP(requested.AsSlice())))
	}
	return m
}

func TestDiscoverGetsAnOfferWithOurOptions(t *testing.T) {
	s, _ := newTestServer(t)
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, discover("aa:aa:aa:aa:aa:aa", "laptop"))

	replies := c.replies(t)
	if len(replies) != 1 {
		t.Fatalf("got %d replies to a DISCOVER, want 1", len(replies))
	}
	r := replies[0]
	if r.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("message type = %v, want OFFER", r.MessageType())
	}
	if want := netip.MustParseAddr("192.168.1.10"); r.YourIPAddr.String() != want.String() {
		t.Fatalf("offered %v, want %v", r.YourIPAddr, want)
	}
	if got := r.Router(); len(got) != 1 || got[0].String() != "192.168.1.1" {
		t.Fatalf("router option = %v, want 192.168.1.1", got)
	}
	if got := r.DNS(); len(got) != 1 || got[0].String() != "192.168.1.5" {
		t.Fatalf("dns option = %v, want ourselves at 192.168.1.5", got)
	}
	if got := r.DomainName(); got != "home.arpa" {
		t.Fatalf("domain option = %q, want home.arpa", got)
	}
	if got := r.IPAddressLeaseTime(0); got != 24*time.Hour {
		t.Fatalf("lease time = %v, want 24h", got)
	}
	if got := r.ServerIdentifier(); got.String() != "192.168.1.5" {
		t.Fatalf("server identifier = %v, want 192.168.1.5", got)
	}
}

func TestDiscoverDoesNotPersistALease(t *testing.T) {
	s, ms := newTestServer(t)
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, discover("aa:aa:aa:aa:aa:aa", "laptop"))
	got, _ := ms.DHCPLeases()
	if len(got) != 0 {
		t.Fatalf("a DISCOVER persisted %d leases; only a REQUEST commits", len(got))
	}
}

func TestRequestGetsAnAckAndPersists(t *testing.T) {
	s, ms := newTestServer(t)
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}))

	replies := c.replies(t)
	if len(replies) != 1 || replies[0].MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("replies = %+v, want one ACK", replies)
	}
	got, _ := ms.DHCPLeases()
	if len(got) != 1 {
		t.Fatalf("persisted %d leases, want 1", len(got))
	}
	if got[0].MAC != "aa:aa:aa:aa:aa:aa" || got[0].Hostname != "laptop" {
		t.Fatalf("persisted %+v, want the requesting client", got[0])
	}
}

func TestRequestForAnAddressWeDoNotControlIsNaked(t *testing.T) {
	s, _ := newTestServer(t)
	c := &captureConn{}
	// A client roaming from another network asks to keep an address that is
	// not in our subnet at all.
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero},
		request("aa:aa:aa:aa:aa:aa", "laptop", netip.MustParseAddr("10.9.9.9")))

	replies := c.replies(t)
	if len(replies) != 1 || replies[0].MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("replies = %+v, want one NAK", replies)
	}
}

func TestReleaseFreesTheAddress(t *testing.T) {
	s, ms := newTestServer(t)
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}))

	rel := discover("aa:aa:aa:aa:aa:aa", "laptop")
	rel.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRelease))
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, rel)

	if n := len(c.replies(t)); n != 0 {
		t.Fatalf("RELEASE drew %d replies, want none", n)
	}
	got, _ := ms.DHCPLeases()
	if len(got) != 0 {
		t.Fatalf("leases after RELEASE = %+v, want none", got)
	}
}

func TestDeclineQuarantinesTheAddress(t *testing.T) {
	s, _ := newTestServer(t)
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "one", netip.Addr{}))
	first := c.replies(t)[0].YourIPAddr

	dec := discover("aa:aa:aa:aa:aa:aa", "one")
	dec.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDecline))
	dec.UpdateOption(dhcpv4.OptRequestedIPAddress(first))
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, dec)

	c2 := &captureConn{}
	s.handle(c2, &net.UDPAddr{IP: net.IPv4zero}, request("bb:bb:bb:bb:bb:bb", "two", netip.Addr{}))
	if got := c2.replies(t)[0].YourIPAddr; got.Equal(first) {
		t.Fatalf("re-offered %v after it was declined", got)
	}
}

func TestInformGetsOptionsAndNoAddress(t *testing.T) {
	s, ms := newTestServer(t)
	inf := discover("aa:aa:aa:aa:aa:aa", "laptop")
	inf.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeInform))
	c := &captureConn{}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, inf)

	replies := c.replies(t)
	if len(replies) != 1 || replies[0].MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("replies = %+v, want one ACK", replies)
	}
	if !replies[0].YourIPAddr.Equal(net.IPv4zero) {
		t.Fatalf("INFORM reply carried address %v, want none", replies[0].YourIPAddr)
	}
	if got, _ := ms.DHCPLeases(); len(got) != 0 {
		t.Fatalf("INFORM persisted %d leases, want 0", len(got))
	}
}

func TestSecondClaimOnAHostnameGetsNoName(t *testing.T) {
	s, ms := newTestServer(t)
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}))
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request("bb:bb:bb:bb:bb:bb", "laptop", netip.Addr{}))

	got, _ := ms.DHCPLeases()
	if len(got) != 2 {
		t.Fatalf("persisted %d leases, want 2: the second client still gets an address", len(got))
	}
	named := 0
	for _, l := range got {
		if l.Hostname == "laptop" {
			named++
		}
	}
	if named != 1 {
		t.Fatalf("%d leases claim the name laptop, want exactly 1", named)
	}
}

func TestLeasesImplementsTheDiscoverySource(t *testing.T) {
	s, _ := newTestServer(t)
	s.handle(&captureConn{}, &net.UDPAddr{IP: net.IPv4zero}, request("aa:aa:aa:aa:aa:aa", "laptop", netip.Addr{}))

	ls, err := s.Leases(t.Context())
	if err != nil {
		t.Fatalf("Leases: %v", err)
	}
	if len(ls) != 1 {
		t.Fatalf("Leases returned %d, want 1", len(ls))
	}
	if ls[0].Hostname != "laptop" || ls[0].IP != "192.168.1.10" {
		t.Fatalf("lease = %+v, want laptop at 192.168.1.10", ls[0])
	}
	if s.Name() == "" {
		t.Fatal("Name is empty; it appears in logs and the UI")
	}
}

func TestMalformedPacketsAreDroppedNotFatal(t *testing.T) {
	s, _ := newTestServer(t)
	c := &captureConn{}
	// No message type option at all.
	m, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	s.handle(c, &net.UDPAddr{IP: net.IPv4zero}, m)
	if n := len(c.replies(t)); n != 0 {
		t.Fatalf("a message with no type drew %d replies, want none", n)
	}
}
```

- [ ] **Step 3: Write the implementation**

Create `internal/dhcpd/server.go`. Adjust modifier and accessor names to whatever Step 1 reported.

```go
package dhcpd

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	idhcp "github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// LeaseStore is the store slice this package needs, named here so the
// package does not depend on the whole store.
type LeaseStore interface {
	DHCPLeases() ([]store.DHCPLease, error)
	PutDHCPLease(store.DHCPLease) error
	DeleteDHCPLease(string) error
	DeleteExpiredDHCPLeases(int64) (int, error)
}

type Options struct {
	Iface  IfaceInfo
	Cfg    Config
	DNS    []netip.Addr // option 6, ourselves first
	Domain string       // option 15
	Alloc  *Allocator
	Prober Prober
	Store  LeaseStore
	// OnChange is called when the lease set changes, so the zone snapshot
	// rebuilds immediately rather than at the next poll.
	OnChange func()
	Logger   *slog.Logger
	// Now is injected for tests. Nil means time.Now.
	Now func() time.Time
}

// Server is the built-in DHCPv4 server. It implements discovery/dhcp.Source.
type Server struct {
	opts Options
	now  func() time.Time

	mu  sync.Mutex
	srv *server4.Server
}

func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Prober == nil {
		o.Prober = nopProber{}
	}
	if o.OnChange == nil {
		o.OnChange = func() {}
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Server{opts: o, now: now}
}

func (s *Server) Name() string { return "built-in" }

// Leases satisfies discovery/dhcp.Source. Only named, unexpired leases reach
// DNS: a client that sent no hostname gets an address and nothing else.
func (s *Server) Leases(context.Context) ([]idhcp.Lease, error) {
	var out []idhcp.Lease
	for _, l := range s.opts.Alloc.Leases() {
		if l.Hostname == "" {
			continue
		}
		out = append(out, idhcp.Lease{
			MAC: l.MAC, IP: l.IP.String(), Hostname: l.Hostname, Expires: l.Expires,
		})
	}
	return out, nil
}

// Start binds the listener. It does not check whether the interface
// qualifies: the caller does that, because the caller is the one that reports
// the reason to the operator.
func (s *Server) Start(ctx context.Context) error {
	if err := s.restore(); err != nil {
		return err
	}
	srv, err := server4.NewServer(
		s.opts.Iface.Name,
		&net.UDPAddr{IP: net.IPv4zero, Port: 67},
		s.handle)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.srv = srv
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = s.Stop()
	}()
	go func() {
		if err := srv.Serve(); err != nil && ctx.Err() == nil {
			s.opts.Logger.Error("dhcp server stopped", "error", err)
		}
	}()
	return nil
}

func (s *Server) Stop() error {
	s.mu.Lock()
	srv := s.srv
	s.srv = nil
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Close()
}

// restore loads persisted leases into the allocator, so a restart cannot
// re-issue an address that is still in use. Expired rows are pruned here
// rather than on a timer.
func (s *Server) restore() error {
	if _, err := s.opts.Store.DeleteExpiredDHCPLeases(s.now().Unix()); err != nil {
		return err
	}
	rows, err := s.opts.Store.DHCPLeases()
	if err != nil {
		return err
	}
	var ls []Lease
	for _, r := range rows {
		ip, err := netip.ParseAddr(r.IP)
		if err != nil {
			s.opts.Logger.Warn("dropping an unparseable stored lease", "mac", r.MAC, "ip", r.IP)
			continue
		}
		ls = append(ls, Lease{MAC: r.MAC, IP: ip, Hostname: r.Hostname, Expires: time.Unix(r.ExpiresAt, 0)})
	}
	s.opts.Alloc.Load(ls)
	return nil
}

// handle is the whole packet path. Every test drives this directly, so it
// takes the conn rather than reaching for one.
func (s *Server) handle(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	if m == nil {
		return
	}
	mac := normalizeMAC(m.ClientHWAddr.String())
	switch m.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		s.offer(conn, peer, m, mac)
	case dhcpv4.MessageTypeRequest:
		s.ack(conn, peer, m, mac)
	case dhcpv4.MessageTypeRelease:
		s.opts.Alloc.Release(mac)
		if err := s.opts.Store.DeleteDHCPLease(mac); err != nil {
			s.opts.Logger.Warn("could not delete a released lease", "mac", mac, "error", err)
		}
		s.opts.OnChange()
	case dhcpv4.MessageTypeDecline:
		if ip, ok := netip.AddrFromSlice(m.RequestedIPAddress()); ok {
			s.opts.Alloc.Decline(ip.Unmap())
			s.opts.Logger.Warn("client declined an address as already in use",
				"mac", mac, "ip", ip.Unmap())
		}
		if err := s.opts.Store.DeleteDHCPLease(mac); err != nil {
			s.opts.Logger.Warn("could not delete a declined lease", "mac", mac, "error", err)
		}
		s.opts.OnChange()
	case dhcpv4.MessageTypeInform:
		s.inform(conn, peer, m)
	default:
		// Anything else, including a message with no type at all, is dropped.
	}
}

func (s *Server) offer(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4, mac string) {
	l, ok := s.allocate(mac, m, false)
	if !ok {
		s.opts.Logger.Warn("no free address to offer",
			"mac", mac, "range", s.opts.Cfg.Start.String()+"-"+s.opts.Cfg.End.String())
		return
	}
	s.reply(conn, peer, m, dhcpv4.MessageTypeOffer, l.IP)
}

func (s *Server) ack(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4, mac string) {
	// A client asking to keep an address we do not control must be told so,
	// or it will sit on it until the lease it thinks it has runs out.
	if req, ok := netip.AddrFromSlice(m.RequestedIPAddress()); ok {
		r := req.Unmap()
		if r.IsValid() && !r.IsUnspecified() && !s.opts.Cfg.Subnet.Contains(r) {
			s.nak(conn, peer, m)
			return
		}
	}
	l, ok := s.allocate(mac, m, true)
	if !ok {
		s.nak(conn, peer, m)
		return
	}
	row := store.DHCPLease{
		MAC:       l.MAC,
		IP:        l.IP.String(),
		Hostname:  l.Hostname,
		ExpiresAt: l.Expires.Unix(),
		LastSeen:  s.now().Unix(),
	}
	if err := s.opts.Store.PutDHCPLease(row); err != nil {
		// The allocator has already committed; refusing now would leave the
		// two out of step. Serve the client and say the persistence failed.
		s.opts.Logger.Error("could not persist a lease", "mac", mac, "ip", row.IP, "error", err)
	}
	s.reply(conn, peer, m, dhcpv4.MessageTypeAck, l.IP)
	s.opts.OnChange()
}

// allocate runs the pool rules and the hostname arbitration. commit is false
// for an OFFER, which does not persist and does not claim a name.
func (s *Server) allocate(mac string, m *dhcpv4.DHCPv4, commit bool) (Lease, bool) {
	hostname := sanitizeHostname(m.HostName())
	if hostname != "" && s.opts.Alloc.NameTaken(hostname, mac) {
		s.opts.Logger.Warn("two clients claim one hostname; the later one gets an address and no name",
			"hostname", hostname, "mac", mac)
		hostname = ""
	}
	var requested netip.Addr
	if ip, ok := netip.AddrFromSlice(m.RequestedIPAddress()); ok {
		requested = ip.Unmap()
	}
	l, ok := s.opts.Alloc.Allocate(mac, hostname, requested)
	if !ok {
		return Lease{}, false
	}
	// Probe only an address that is new to us. A renewal or a reservation is
	// not probed: the client already has it, or it is spoken for.
	if !commit && s.opts.Prober.InUse(l.IP) {
		s.opts.Logger.Warn("an address in the pool answered a probe; quarantining it", "ip", l.IP)
		s.opts.Alloc.Quarantine(l.IP)
		s.opts.Alloc.Release(mac)
		return s.opts.Alloc.Allocate(mac, hostname, netip.Addr{})
	}
	return l, true
}

func (s *Server) reply(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4, t dhcpv4.MessageType, yours netip.Addr) {
	self := net.IP(s.opts.Iface.Addr.AsSlice())
	mods := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(t),
		dhcpv4.WithServerIP(self),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(self)),
		dhcpv4.WithOption(dhcpv4.OptSubnetMask(net.CIDRMask(s.opts.Cfg.Subnet.Bits(), 32))),
		dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(s.opts.Cfg.LeaseTime)),
	}
	if yours.IsValid() {
		mods = append(mods, dhcpv4.WithYourIP(net.IP(yours.AsSlice())))
	}
	if s.opts.Cfg.Gateway.IsValid() {
		mods = append(mods, dhcpv4.WithOption(dhcpv4.OptRouter(net.IP(s.opts.Cfg.Gateway.AsSlice()))))
	}
	if dns := toIPs(s.opts.DNS); len(dns) > 0 {
		mods = append(mods, dhcpv4.WithOption(dhcpv4.OptDNS(dns...)))
	}
	if s.opts.Domain != "" {
		mods = append(mods, dhcpv4.WithOption(dhcpv4.OptDomainName(s.opts.Domain)))
	}
	s.send(conn, peer, m, mods...)
}

func (s *Server) nak(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	self := net.IP(s.opts.Iface.Addr.AsSlice())
	s.send(conn, peer, m,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeNak),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(self)))
}

// inform answers a client that has an address already and wants only options.
// No lease is allocated and nothing is persisted.
func (s *Server) inform(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	s.reply(conn, peer, m, dhcpv4.MessageTypeAck, netip.Addr{})
}

// send broadcasts the reply. Every reply is broadcast: a client that has no
// address yet cannot be reached by unicast without a raw socket, and one that
// does is still listening on 0.0.0.0:68.
func (s *Server) send(conn net.PacketConn, _ net.Addr, m *dhcpv4.DHCPv4, mods ...dhcpv4.Modifier) {
	reply, err := dhcpv4.NewReplyFromRequest(m, mods...)
	if err != nil {
		s.opts.Logger.Warn("could not build a dhcp reply", "error", err)
		return
	}
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
	if _, err := conn.WriteTo(reply.ToBytes(), dst); err != nil {
		s.opts.Logger.Warn("could not send a dhcp reply", "error", err)
	}
}

func toIPs(as []netip.Addr) []net.IP {
	out := make([]net.IP, 0, len(as))
	for _, a := range as {
		if a.IsValid() {
			out = append(out, net.IP(a.AsSlice()))
		}
	}
	return out
}
```

- [ ] **Step 4: Add the hostname and MAC helpers**

Still in `internal/dhcpd/server.go`:

```go
// normalizeMAC is the one form a MAC is stored and compared in: lowercase,
// colon-separated. Reservations in Part 2 normalize the same way, so the two
// always compare directly.
func normalizeMAC(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// sanitizeHostname reduces option 12 to something safe to publish as a DNS
// label, or to "" if it cannot be. Option 12 is chosen by any device on the
// segment, so this is untrusted input.
func sanitizeHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i] // a client may send an FQDN; we own the domain
	}
	if h == "" || len(h) > 63 {
		return ""
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return ""
		}
	}
	if h[0] == '-' || h[len(h)-1] == '-' {
		return ""
	}
	return h
}
```

Add `"strings"` to the import block.

- [ ] **Step 5: Write the hostname tests**

Append to `internal/dhcpd/server_test.go`:

```go
func TestSanitizeHostname(t *testing.T) {
	cases := []struct{ in, want string }{
		{"laptop", "laptop"},
		{"LAPTOP", "laptop"},
		{"  laptop  ", "laptop"},
		{"laptop.lan", "laptop"},
		{"my-laptop-2", "my-laptop-2"},
		{"", ""},
		{"-leading", ""},
		{"trailing-", ""},
		{"has space", ""},
		{"has_underscore", ""},
		{"inject\x00null", ""},
		{"wildcard*", ""},
		{strings.Repeat("a", 64), ""},
		{strings.Repeat("a", 63), strings.Repeat("a", 63)},
	}
	for _, c := range cases {
		if got := sanitizeHostname(c.in); got != c.want {
			t.Fatalf("sanitizeHostname(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
```

Add `"strings"` to the test file's imports.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/dhcpd/ -v`
Expected: PASS, every test in the package.

- [ ] **Step 7: Prove the source contract holds**

Run: `go build ./... && go vet ./internal/dhcpd/`
Expected: no output. Then add this compile-time assertion at the top of `internal/dhcpd/server.go`, below the imports, and rebuild:

```go
// The whole point of this package's shape: leases reach DNS through the path
// lease-file discovery already uses.
var _ idhcp.Source = (*Server)(nil)
```

Run: `go build ./internal/dhcpd/`
Expected: no output. A failure here means the interface drifted and the wiring in Task 8 will not compile.

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum internal/dhcpd/server.go internal/dhcpd/server_test.go
git commit -m "feat(dhcpd): DHCPv4 packet handling

DISCOVER/OFFER, REQUEST/ACK/NAK, DECLINE, RELEASE, INFORM. Implements
discovery/dhcp.Source, so leases reach DNS through the path lease-file
discovery already uses. Every packet test drives handle() against a fake
PacketConn; no test opens a socket.

Option 12 is client-chosen, so hostnames are sanitized to a single DNS
label and the second claim on a name gets an address and no name."
```

---

### Task 8: Rogue-server detection

**Files:**
- Create: `internal/dhcpd/rogue.go`
- Test: `internal/dhcpd/rogue_test.go`

**Interfaces:**
- Produces: `type Foreign struct { ServerID netip.Addr; Offered netip.Addr }`, `func DetectForeign(ctx context.Context, iface string, wait time.Duration, self netip.Addr) ([]Foreign, error)`, and the testable core `func collectForeign(replies []*dhcpv4.DHCPv4, self netip.Addr) []Foreign`.

- [ ] **Step 1: Write the failing tests**

Create `internal/dhcpd/rogue_test.go`:

```go
package dhcpd

import (
	"net"
	"net/netip"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func offerFrom(serverID, offered string) *dhcpv4.DHCPv4 {
	m, err := dhcpv4.New()
	if err != nil {
		panic(err)
	}
	m.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
	m.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP(serverID)))
	m.YourIPAddr = net.ParseIP(offered)
	return m
}

func TestCollectForeignIgnoresOurOwnOffers(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.5")
	got := collectForeign([]*dhcpv4.DHCPv4{offerFrom("192.168.1.5", "192.168.1.10")}, self)
	if len(got) != 0 {
		t.Fatalf("collectForeign = %+v, want none: that offer is ours", got)
	}
}

func TestCollectForeignReportsAnotherServer(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.5")
	got := collectForeign([]*dhcpv4.DHCPv4{offerFrom("192.168.1.1", "192.168.1.64")}, self)
	if len(got) != 1 {
		t.Fatalf("collectForeign = %+v, want one entry", got)
	}
	if got[0].ServerID.String() != "192.168.1.1" || got[0].Offered.String() != "192.168.1.64" {
		t.Fatalf("entry = %+v, want server 192.168.1.1 offering 192.168.1.64", got[0])
	}
}

func TestCollectForeignDedupesOneServerAnsweringTwice(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.5")
	got := collectForeign([]*dhcpv4.DHCPv4{
		offerFrom("192.168.1.1", "192.168.1.64"),
		offerFrom("192.168.1.1", "192.168.1.64"),
	}, self)
	if len(got) != 1 {
		t.Fatalf("collectForeign = %+v, want one entry after dedupe", got)
	}
}

func TestCollectForeignIgnoresNonOffers(t *testing.T) {
	self := netip.MustParseAddr("192.168.1.5")
	ack := offerFrom("192.168.1.1", "192.168.1.64")
	ack.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
	if got := collectForeign([]*dhcpv4.DHCPv4{ack}, self); len(got) != 0 {
		t.Fatalf("collectForeign = %+v, want none: an ACK is not an offer of service", got)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/dhcpd/ -run Foreign -v`
Expected: FAIL to compile with `undefined: collectForeign`.

- [ ] **Step 3: Write the implementation**

Create `internal/dhcpd/rogue.go`:

```go
package dhcpd

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// Foreign is one other DHCP server that answered a probe.
type Foreign struct {
	ServerID netip.Addr
	Offered  netip.Addr
}

func (f Foreign) String() string {
	return fmt.Sprintf("%s (offering %s)", f.ServerID, f.Offered)
}

// DetectForeign broadcasts a DISCOVER from a random locally-administered MAC
// and collects OFFERs from anyone that is not us. A positive result is what
// refuses to start the listener: two DHCP servers on one segment breaks the
// network, not one name.
func DetectForeign(ctx context.Context, iface string, wait time.Duration, self netip.Addr) ([]Foreign, error) {
	mac, err := probeMAC()
	if err != nil {
		return nil, err
	}
	discover, err := dhcpv4.NewDiscovery(mac)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenPacket("udp4", ":68")
	if err != nil {
		return nil, fmt.Errorf("probe socket: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(wait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.WriteTo(discover.ToBytes(), &net.UDPAddr{IP: net.IPv4bcast, Port: 67}); err != nil {
		return nil, fmt.Errorf("probe send: %w", err)
	}

	var replies []*dhcpv4.DHCPv4
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break // deadline; that is the whole wait
		}
		m, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			continue
		}
		if !strings.EqualFold(m.ClientHWAddr.String(), mac.String()) {
			continue // an answer to somebody else's DISCOVER
		}
		replies = append(replies, m)
	}
	return collectForeign(replies, self), nil
}

// collectForeign is the decision, split out so it is testable without a
// network. Only OFFERs count, and only from a server identifier that is not
// ours.
func collectForeign(replies []*dhcpv4.DHCPv4, self netip.Addr) []Foreign {
	seen := map[netip.Addr]bool{}
	var out []Foreign
	for _, m := range replies {
		if m.MessageType() != dhcpv4.MessageTypeOffer {
			continue
		}
		id, ok := netip.AddrFromSlice(m.ServerIdentifier())
		if !ok {
			continue
		}
		id = id.Unmap()
		if !id.IsValid() || id == self || seen[id] {
			continue
		}
		offered, _ := netip.AddrFromSlice(m.YourIPAddr)
		seen[id] = true
		out = append(out, Foreign{ServerID: id, Offered: offered.Unmap()})
	}
	return out
}

// probeMAC returns a random locally-administered unicast MAC, so the probe
// cannot be mistaken for a real client and cannot collide with one.
func probeMAC() (net.HardwareAddr, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	b[0] = (b[0] | 0x02) &^ 0x01 // locally administered, unicast
	return net.HardwareAddr(b), nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/dhcpd/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/dhcpd/rogue.go internal/dhcpd/rogue_test.go
git commit -m "feat(dhcpd): detect another DHCP server before binding

A DISCOVER from a random locally-administered MAC, and any OFFER whose
server identifier is not ours refuses the start. The decision is split
from the socket so it is tested without a network."
```

---

### Task 9: Settings validation

**Files:**
- Modify: `internal/settings/validate.go`
- Test: `internal/settings/validate_test.go`

**Interfaces:**
- Consumes: `store.Settings` DHCP fields (Task 2).
- Produces: `ValidateStored` rejects a bad DHCP configuration with a `FieldError` naming the offending key.

- [ ] **Step 1: Write the failing tests**

Add to `internal/settings/validate_test.go`. `validSettings()` is the existing helper that returns a settings value the tests mutate — reuse it.

```go
func dhcpSettings() store.Settings {
	v := validSettings()
	v.DHCPEnabled = true
	v.DHCPInterface = "eth0"
	v.DHCPRangeStart = "192.168.1.128"
	v.DHCPRangeEnd = "192.168.1.254"
	v.DHCPGateway = "192.168.1.1"
	v.DHCPLeaseSeconds = 86400
	return v
}

func TestDHCPValidationAcceptsAGoodConfiguration(t *testing.T) {
	if err := ValidateStored(dhcpSettings()); err != nil {
		t.Fatalf("ValidateStored rejected a valid DHCP configuration: %v", err)
	}
}

func TestDHCPDisabledIgnoresEveryOtherField(t *testing.T) {
	v := dhcpSettings()
	v.DHCPEnabled = false
	v.DHCPInterface = ""
	v.DHCPRangeStart = "nonsense"
	if err := ValidateStored(v); err != nil {
		t.Fatalf("ValidateStored rejected a disabled DHCP configuration: %v", err)
	}
}

func TestDHCPValidationRejects(t *testing.T) {
	cases := []struct {
		name  string
		mutate func(*store.Settings)
		field string
	}{
		{"no interface", func(v *store.Settings) { v.DHCPInterface = "" }, "dhcp.interface"},
		{"unparseable start", func(v *store.Settings) { v.DHCPRangeStart = "nope" }, "dhcp.range_start"},
		{"unparseable end", func(v *store.Settings) { v.DHCPRangeEnd = "nope" }, "dhcp.range_end"},
		{"ipv6 start", func(v *store.Settings) { v.DHCPRangeStart = "2001:db8::1" }, "dhcp.range_start"},
		{"end below start", func(v *store.Settings) {
			v.DHCPRangeStart, v.DHCPRangeEnd = "192.168.1.254", "192.168.1.128"
		}, "dhcp.range_end"},
		{"end in another subnet", func(v *store.Settings) { v.DHCPRangeEnd = "10.0.0.5" }, "dhcp.range_end"},
		{"unparseable gateway", func(v *store.Settings) { v.DHCPGateway = "nope" }, "dhcp.gateway"},
		{"lease too short", func(v *store.Settings) { v.DHCPLeaseSeconds = 299 }, "dhcp.lease_seconds"},
		{"lease too long", func(v *store.Settings) { v.DHCPLeaseSeconds = 604801 }, "dhcp.lease_seconds"},
		{"unparseable secondary dns", func(v *store.Settings) { v.DHCPSecondaryDNS = "nope" }, "dhcp.secondary_dns"},
		{"lease file at the same time", func(v *store.Settings) { v.DHCPLeaseFile = "/var/lib/misc/dnsmasq.leases" }, "dhcp.enabled"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := dhcpSettings()
			c.mutate(&v)
			err := ValidateStored(v)
			if err == nil {
				t.Fatalf("ValidateStored accepted %s", c.name)
			}
			var fe FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("error %v is not a FieldError; the form cannot highlight a field", err)
			}
			if fe.Field != c.field {
				t.Fatalf("error names field %q, want %q", fe.Field, c.field)
			}
		})
	}
}

func TestDHCPLeaseSecondsBoundariesAreInclusive(t *testing.T) {
	for _, secs := range []int{300, 604800} {
		v := dhcpSettings()
		v.DHCPLeaseSeconds = secs
		if err := ValidateStored(v); err != nil {
			t.Fatalf("ValidateStored rejected the boundary value %d: %v", secs, err)
		}
	}
}
```

Add `"errors"` to the test file's imports if it is not already there.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/settings/ -run DHCP -v`
Expected: FAIL — `ValidateStored accepted no interface`, and so on.

- [ ] **Step 3: Write the implementation**

Add to `internal/settings/validate.go`, and call it from `ValidateStored` just before its final `return nil`:

```go
	if err := validateDHCP(v); err != nil {
		return err
	}
```

```go
// dhcpLeaseMin and dhcpLeaseMax bound the lease time. The floor keeps a
// misconfiguration from turning into a broadcast storm; the ceiling is a
// week, past which a lease outlives most of the reasons to have one.
const (
	dhcpLeaseMin = 300
	dhcpLeaseMax = 604800
)

// validateDHCP checks the built-in server's configuration. Every rule is
// skipped when it is off, so an operator can leave a half-filled form behind
// without it blocking every unrelated save.
//
// What is deliberately not checked here: whether the interface exists, is up,
// or can serve DHCP. That is a property of the host at this moment, not of
// the stored value, and dhcpd.Qualifies reports it where the operator can act
// on it.
func validateDHCP(v store.Settings) error {
	if !v.DHCPEnabled {
		return nil
	}
	if v.DHCPLeaseFile != "" {
		return bad("dhcp.enabled",
			"the built-in DHCP server and dhcp_lease_file cannot both be on; clear dhcp_lease_file first")
	}
	if strings.TrimSpace(v.DHCPInterface) == "" {
		return bad("dhcp.interface", "an interface is required to serve DHCP")
	}
	start, err := parseIPv4("dhcp.range_start", v.DHCPRangeStart)
	if err != nil {
		return err
	}
	end, err := parseIPv4("dhcp.range_end", v.DHCPRangeEnd)
	if err != nil {
		return err
	}
	if end.Less(start) {
		return bad("dhcp.range_end", "%s is below the range start %s", end, start)
	}
	if _, err := parseIPv4("dhcp.gateway", v.DHCPGateway); err != nil {
		return err
	}
	if v.DHCPSecondaryDNS != "" {
		if _, err := parseIPv4("dhcp.secondary_dns", v.DHCPSecondaryDNS); err != nil {
			return err
		}
	}
	if v.DHCPLeaseSeconds < dhcpLeaseMin || v.DHCPLeaseSeconds > dhcpLeaseMax {
		return bad("dhcp.lease_seconds", "must be between %d and %d seconds", dhcpLeaseMin, dhcpLeaseMax)
	}
	return nil
}

func parseIPv4(field, s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, bad(field, "%q is not an IP address", s)
	}
	if !a.Is4() {
		return netip.Addr{}, bad(field, "%q is not an IPv4 address; the built-in DHCP server is IPv4 only", s)
	}
	return a, nil
}
```

The "end in another subnet" case is caught by `end.Less(start)` only when the other subnet is numerically lower. Add the explicit check after the `Less` comparison:

```go
	// A range must sit inside one subnet, and the /24 the start implies is
	// the closest thing to that available without reading the interface.
	if start.As4()[0] != end.As4()[0] || start.As4()[1] != end.As4()[1] || start.As4()[2] != end.As4()[2] {
		return bad("dhcp.range_end", "%s is not in the same /24 as the range start %s", end, start)
	}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/settings/... -v`
Expected: PASS, including every pre-existing settings test.

- [ ] **Step 5: Commit**

```bash
git add internal/settings/validate.go internal/settings/validate_test.go
git commit -m "feat(settings): validate the built-in DHCP configuration

Every rule is skipped when DHCP is off, so a half-filled form does not
block unrelated saves. Whether the interface can actually serve DHCP is
deliberately not checked here: that is a property of the host right now,
not of the stored value."
```

---

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

### Task 11: API and CLI surface

**Files:**
- Modify: `internal/adminapi/settings.go`, `internal/adminapi/api.go` (route table), `internal/cli/settings.go`
- Test: `internal/adminapi/settings_test.go`, `internal/adminapi/dhcp_test.go`, `internal/cli/settings_test.go`

**Interfaces:**
- Produces: the seven `dhcp_*` fields in the settings JSON; `GET /api/dhcp/leases` returning `{"running":bool,"error":string,"leases":[{"mac","ip","hostname","expires"}]}`.

- [ ] **Step 1: Write the failing tests**

Create `internal/adminapi/dhcp_test.go`:

```go
package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSettingsJSONCarriesDHCPFields(t *testing.T) {
	h, tok := newTestAPI(t) // the existing helper in this package
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{
		"dhcp_enabled", "dhcp_interface", "dhcp_range_start", "dhcp_range_end",
		"dhcp_gateway", "dhcp_lease_seconds", "dhcp_secondary_dns",
	} {
		if _, ok := body[k]; !ok {
			t.Fatalf("settings JSON has no %q; the CLI and UI read this", k)
		}
	}
}

func TestDHCPLeasesEndpointReportsNotRunning(t *testing.T) {
	h, tok := newTestAPI(t)
	req := httptest.NewRequest(http.MethodGet, "/api/dhcp/leases", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even when DHCP is off", rec.Code)
	}
	var body struct {
		Running bool `json:"running"`
		Leases  []struct{ MAC string } `json:"leases"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Running {
		t.Fatal("running = true with DHCP disabled")
	}
	if len(body.Leases) != 0 {
		t.Fatalf("leases = %+v, want none", body.Leases)
	}
}

func TestDHCPLeasesRequiresAuth(t *testing.T) {
	h, _ := newTestAPI(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/dhcp/leases", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: lease data names devices on the network", rec.Code)
	}
}

func TestDHCPSettingsRejectedOnAReplica(t *testing.T) {
	// A replica refuses administrative writes with the address of the node to
	// make them on. DHCP settings are no exception.
	h, tok := newTestReplicaAPI(t) // the existing helper used by writegate_test.go
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"dhcp_enabled":true}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("a replica accepted a settings write")
	}
}
```

Use the helper names this package already has — check `internal/adminapi/settings_test.go` and `writegate_test.go` for what `newTestAPI` and the replica equivalent are actually called, and do not add new ones.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/adminapi/ -run DHCP -v`
Expected: FAIL — the settings JSON has no `dhcp_enabled`, and `/api/dhcp/leases` 404s.

- [ ] **Step 3: Add the settings fields**

In `internal/adminapi/settings.go`, add to the settings DTO, matching the existing `json` tag style:

```go
	DHCPEnabled      bool   `json:"dhcp_enabled"`
	DHCPInterface    string `json:"dhcp_interface"`
	DHCPRangeStart   string `json:"dhcp_range_start"`
	DHCPRangeEnd     string `json:"dhcp_range_end"`
	DHCPGateway      string `json:"dhcp_gateway"`
	DHCPLeaseSeconds int    `json:"dhcp_lease_seconds"`
	DHCPSecondaryDNS string `json:"dhcp_secondary_dns"`
```

Wire them through both directions of the existing DTO-to-`store.Settings` conversion. Follow whatever pattern the neighbouring fields use; do not introduce a second one.

- [ ] **Step 4: Add the lease endpoint**

Create `internal/adminapi/dhcp.go`:

```go
package adminapi

import (
	"net/http"
	"time"
)

// DHCPStatus is what the leases endpoint returns. It reports running and any
// error separately from the lease list, because "no leases" and "not running"
// are different things an operator needs told apart.
type DHCPStatus struct {
	Running bool        `json:"running"`
	Error   string      `json:"error,omitempty"`
	Leases  []DHCPLease `json:"leases"`
}

type DHCPLease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Expires  string `json:"expires"`
}

func (a *API) dhcpLeases(w http.ResponseWriter, r *http.Request) {
	out := DHCPStatus{Leases: []DHCPLease{}}
	if a.DHCP != nil {
		running, err := a.DHCP.Status()
		out.Running = running
		if err != nil {
			out.Error = err.Error()
		}
	}
	if a.Leases != nil {
		for _, l := range a.Leases() {
			out.Leases = append(out.Leases, DHCPLease{
				MAC:      l.MAC,
				IP:       l.IP,
				Hostname: l.Hostname,
				Expires:  l.Expires.Format(time.RFC3339),
			})
		}
	}
	writeJSON(w, http.StatusOK, out)
}
```

`a.Leases` is the existing `func() []dhcp.Lease` field wired at `internal/app/serve.go:313`. Add a `DHCP` field to the `API` struct with an interface type declared next to it:

```go
	// DHCPStatuser is the runner slice the API needs. It is nil when the
	// build has no DHCP runner, which is every test that does not want one.
	DHCP interface{ Status() (bool, error) }
```

Register the route beside the other read-only endpoints in `internal/adminapi/api.go`, behind the same auth middleware:

```go
	mux.HandleFunc("GET /api/dhcp/leases", a.dhcpLeases)
```

Use whatever registration form the neighbouring routes use.

- [ ] **Step 5: Pass the runner in**

In `internal/app/serve.go`, where the `adminapi.API` is constructed, add `DHCP: dhcpRun`.

- [ ] **Step 6: Add the CLI**

In `internal/cli/settings.go`, add the seven keys to the settings get/set table so `kydns settings set dhcp.enabled true` works. Follow the existing key-name convention exactly — if other keys are dotted (`health.interval`), these are `dhcp.enabled`, `dhcp.interface`, `dhcp.range_start`, `dhcp.range_end`, `dhcp.gateway`, `dhcp.lease_seconds`, `dhcp.secondary_dns`.

Add a `kydns dhcp leases` command that GETs `/api/dhcp/leases` and prints a table, matching how the CLI renders other lists. When `running` is false and `error` is non-empty, print the error instead of an empty table — an operator who enabled DHCP and sees nothing needs the reason, not a blank.

- [ ] **Step 7: Write the CLI test**

Add to `internal/cli/settings_test.go`, following the pattern the existing tests in that file use for a fake API server:

```go
func TestSettingsSetDHCPEnabled(t *testing.T) {
	var got map[string]any
	srv := fakeAPI(t, func(body map[string]any) { got = body })
	defer srv.Close()

	if err := run(t, srv.URL, "settings", "set", "dhcp.enabled", "true"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got["dhcp_enabled"] != true {
		t.Fatalf("PUT body dhcp_enabled = %v, want true", got["dhcp_enabled"])
	}
}
```

`fakeAPI` and `run` are placeholders for whatever this file already uses. Read the neighbouring test before writing this one and match it.

- [ ] **Step 8: Run the tests**

Run: `go test ./internal/adminapi/... ./internal/cli/... -v`
Expected: PASS.

- [ ] **Step 9: Run the whole suite**

Run: `go test ./... -count=1 && go vet ./...`
Expected: PASS, no vet output.

- [ ] **Step 10: Commit**

```bash
git add internal/adminapi/ internal/cli/ internal/app/serve.go
git commit -m "feat(api,cli): expose DHCP settings and the lease table

Running and error are reported separately from the lease list: 'no
leases' and 'not running' are different things, and an operator who
turned DHCP on and sees nothing needs the reason rather than a blank."
```

---

## Self-Review

**Spec coverage.** Every section of the spec that Part 1 owns maps to a task: sockets and the broadcast decision (Task 7), settings and the live-apply change (Tasks 2, 9, 10), lease allocation and the store (Tasks 3, 5), conflict probing (Task 6), rogue detection (Tasks 8, 10), replication's primary-only rule (Task 10, `dhcpWanted`), the operator surface for API and CLI (Task 11), and packaging (Task 10, Step 7).

Deferred to Part 2, by design: reservations as a MAC on `Service` (the spec's "Reservations" section), the setup wizard, the web DHCP tab, the dual-stack note, the periodic 15-minute rogue probe and its banner, and the documentation updates. Task 5 ships `SetReservations` unused so Part 2 has the seam it needs without reopening the allocator.

**Known gap carried into Part 2.** Task 10's `build` treats a foreign server as a hard refusal with no override. The spec requires an override that is off by default; it needs a settings field and a UI affordance, so it lands with the DHCP tab in Part 2. Until then the behaviour is stricter than the spec, not looser — an operator who genuinely runs two servers cannot enable DHCP yet. That is the safe direction to be wrong in, and Part 2 Task 1 closes it.

**Type consistency.** `Lease` is `dhcpd.Lease` (netip, time.Time) inside the package, `store.DHCPLease` (strings, Unix seconds) at the storage boundary, and `discovery/dhcp.Lease` at the DNS boundary; `Server.Leases` is the only conversion between the last two, and `Server.restore` the only one between the first two. MAC normalization is `normalizeMAC` in one place, and Part 2's reservations must call it.
