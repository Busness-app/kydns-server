# Settings in the Web UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move every KyDNS setting that can move out of `kydns.yaml` and into the database, editable from the web UI, JSON API, and CLI, applied live where possible.

**Architecture:** A new `internal/settings` package owns an immutable snapshot behind an `atomic.Pointer`, mirroring the existing `policy.Holder` and `zone.Holder`. Runtime components grow narrow swap methods that are single atomic stores, and `internal/app` owns the one `apply` that fans out to them. The YAML file seeds the database on first run and is ignored for those keys afterwards.

**Tech Stack:** Go 1.22+, `modernc.org/sqlite` (pure Go, no cgo), `miekg/dns`, `html/template`, stdlib `net/http` with Go 1.22 method+pattern routing.

**Spec:** `docs/superpowers/specs/2026-08-13-kydns-settings-in-the-ui-design.md`

## Global Constraints

- The build must stay cgo-free. The image is distroless, so the pure-Go SQLite driver is not optional. Never add a dependency that needs cgo.
- Every write goes through `internal/store`. No other package opens the database.
- The DNS hot path must stay lock-free for reads: readers load an `atomic.Pointer`, they never take a mutex.
- Default-closed security: an empty `allow_query` refuses everything and must be rejected by validation, never silently widened.
- Logging never records client identity unless `log_client_ip` is on. Counters say what happened, never who asked.
- One concern per package, per `AGENTS.md`. Run a DOX pass and update the nearest owning `AGENTS.md` when behaviour changes.
- Non-trivial logic ships with one runnable check. `go test ./... -race` must pass before every commit.
- Comments are short and meaningful. If a block of comment is needed to defend why code is not wrong, the code is wrong.

## Deviations from the spec

Two, both to match conventions already in the codebase. Note them in the commit that introduces them.

1. **`PATCH /api/v1/settings`, not `PUT`.** The existing partial update on `/api/v1/blacklists/settings` and `/api/v1/services/{id}` is PATCH. Same semantics the spec asked for.
2. **Decode-onto-current, not pointer fields.** `patchBlacklistSettings` pre-fills the decode target with the current values, so an absent JSON key keeps its value without any pointer plumbing. An explicit `[]` still clears a list, which is the behaviour the spec wanted.

## File Structure

**Created**

| File | Responsibility |
|---|---|
| `internal/settings/settings.go` | `Snapshot`, `Build`, `Holder`, `Service`. The live settings, and the one write path. |
| `internal/settings/validate.go` | `Validate`. Every rule that decides whether settings may be stored. |
| `internal/settings/settings_test.go`, `validate_test.go` | Tests for the above. |
| `internal/store/settings.go` | The `settings` table: read, write, seed-once. |
| `internal/store/settings_test.go` | Round-trip, list order, migration onto an old database. |
| `internal/adminapi/settings.go` | `GET`/`PATCH /api/v1/settings`. |
| `internal/adminapi/settings_test.go` | Partial patch, guardrail rejection, export round-trip. |
| `internal/web/serversettings.go` | The Server settings card and its POST handler. |
| `internal/web/serversettings_test.go` | Form render, save, field-level error, CSRF. |
| `internal/cli/settings.go` | `kydns settings get` and `kydns settings set`. |
| `internal/cli/settings_test.go` | Argument parsing and request shape. |

**Modified**

| File | Change |
|---|---|
| `internal/store/model.go` | Add the `Settings` struct. |
| `internal/store/store.go` | Add the `settings` table to `schema` and a `migrations` entry. |
| `internal/config/config.go` | Add `SeedSettings()`. Keep parsing every key; move the moved keys' validation out. |
| `internal/config/example_test.go` | Assert against the reduced example file. |
| `internal/dnsserver/acl.go` | `ACL.Replace`. |
| `internal/dnsserver/forward.go` | `Forwarder.Replace`, state behind an atomic pointer. |
| `internal/dnsserver/cache.go` | `Cache.Retune`. |
| `internal/dnsserver/server.go` | `Server.SetLogging`, atomic log flags. |
| `internal/dnsserver/auth.go` | `Authoritative.SetTTL`, `SetReverseZones`. |
| `internal/health/checker.go` | `Checker.Reconfigure`, timer-per-loop instead of a fixed ticker. |
| `internal/discovery/poller.go` | `Poller.SetInterval`, same timer change. |
| `internal/app/serve.go` | Read settings from the store, seed on first run, own `apply`, track restart-pending. |
| `internal/adminapi/api.go` | `WithSettings`, settings in the export document. |
| `internal/web/middleware.go` | `Settings` and `RestartPending` in `Options`. |
| `internal/web/settings.go` | `configRows` shrinks to the three file-owned keys. |
| `internal/web/templates/settings.html` | The Server settings card. |
| `internal/web/templates/dashboard.html` | Public-ACL warning banner. |
| `internal/cli/cli.go`, `cmd/kydns/main.go` | Dispatch `settings`. |
| `kydns.example.yaml`, `kydns.docker.yaml`, `README.md`, `AGENTS.md`, `SECURITY.md`, `DESGINE.md` | Documentation. |

---

### Task 1: The settings table

**Files:**
- Modify: `internal/store/model.go`
- Modify: `internal/store/store.go` (the `schema` constant and the `migrations` slice)
- Create: `internal/store/settings.go`
- Test: `internal/store/settings_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `store.Settings` struct (fields below)
  - `func (s *Store) Settings() (Settings, bool, error)` — the stored settings and whether a row exists
  - `func (s *Store) PutSettings(v Settings) error`

- [ ] **Step 1: Write the failing test**

Create `internal/store/settings_test.go`:

```go
package store

import (
	"reflect"
	"testing"
)

func TestSettingsRoundTrip(t *testing.T) {
	st := testStore(t)

	if _, ok, err := st.Settings(); err != nil {
		t.Fatalf("Settings on a fresh database: %v", err)
	} else if ok {
		t.Fatal("a fresh database reports a settings row; it must report none so the seed can run")
	}

	want := Settings{
		PrivateDomain:     "home.arpa",
		ReverseZones:      []string{"192.168.1.0/24", "10.0.0.0/8"},
		Upstreams:         []string{"tls://1.1.1.1:853", "tls://9.9.9.9:853"},
		AllowQuery:        []string{"127.0.0.0/8", "192.168.0.0/16"},
		AllowTailscale:    true,
		TTL:               60,
		CacheMinTTL:       5,
		CacheMaxTTL:       3600,
		NegativeMaxTTL:    300,
		CacheEntries:      10000,
		LogQueries:        true,
		LogClientIP:       false,
		DHCPLeaseFile:     "/var/lib/misc/dnsmasq.leases",
		DiscoveryInterval: 30,
		HealthInterval:    30,
		HealthTimeout:     5,
		HealthWorkers:     8,
	}
	if err := st.PutSettings(want); err != nil {
		t.Fatalf("PutSettings: %v", err)
	}

	got, ok, err := st.Settings()
	if err != nil || !ok {
		t.Fatalf("Settings after write: ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip differs\n got %+v\nwant %+v", got, want)
	}
	// Upstreams are tried in order, so order is data, not presentation.
	if got.Upstreams[0] != "tls://1.1.1.1:853" {
		t.Errorf("upstream order lost: %v", got.Upstreams)
	}
}

// A second write must update the single row rather than fail or accumulate.
func TestPutSettingsReplaces(t *testing.T) {
	st := testStore(t)
	if err := st.PutSettings(Settings{PrivateDomain: "a.example", TTL: 10}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := st.PutSettings(Settings{PrivateDomain: "b.example", TTL: 20}); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, _, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if got.PrivateDomain != "b.example" || got.TTL != 20 {
		t.Errorf("second write did not replace the row: %+v", got)
	}
}

// An empty list must survive as empty rather than come back as [""].
func TestSettingsEmptyLists(t *testing.T) {
	st := testStore(t)
	if err := st.PutSettings(Settings{PrivateDomain: "home.arpa"}); err != nil {
		t.Fatal(err)
	}
	got, _, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ReverseZones) != 0 {
		t.Errorf("empty reverse_zones came back as %#v", got.ReverseZones)
	}
}
```

Check what the existing helper for opening a temporary store is called before writing these: run `grep -n "func testStore\|func newTestStore\|t.TempDir" internal/store/store_test.go | head`. Use whatever name is already there rather than adding a second helper.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/store/ -run TestSettings -v`
Expected: FAIL, compile error — `st.Settings undefined`, `store.Settings` type undefined.

- [ ] **Step 3: Add the struct**

Append to `internal/store/model.go`:

```go
// Settings is the process configuration that lives in the database rather than
// the config file. data_dir and the two listen addresses are not here: they are
// needed before the database is open.
type Settings struct {
	PrivateDomain     string
	ReverseZones      []string
	Upstreams         []string
	AllowQuery        []string
	AllowTailscale    bool
	TTL               int
	CacheMinTTL       int
	CacheMaxTTL       int
	NegativeMaxTTL    int
	CacheEntries      int
	LogQueries        bool
	LogClientIP       bool
	DHCPLeaseFile     string
	DiscoveryInterval int
	HealthInterval    int
	HealthTimeout     int
	HealthWorkers     int
}
```

- [ ] **Step 4: Add the schema and the migration**

In `internal/store/store.go`, append to the `schema` constant:

```sql
CREATE TABLE IF NOT EXISTS settings (
  id                 INTEGER PRIMARY KEY CHECK (id = 1),
  private_domain     TEXT NOT NULL,
  reverse_zones      TEXT NOT NULL,
  upstreams          TEXT NOT NULL,
  allow_query        TEXT NOT NULL,
  allow_tailscale    INTEGER NOT NULL,
  ttl                INTEGER NOT NULL,
  cache_min_ttl      INTEGER NOT NULL,
  cache_max_ttl      INTEGER NOT NULL,
  negative_max_ttl   INTEGER NOT NULL,
  cache_entries      INTEGER NOT NULL,
  log_queries        INTEGER NOT NULL,
  log_client_ip      INTEGER NOT NULL,
  dhcp_lease_file    TEXT NOT NULL,
  discovery_interval INTEGER NOT NULL,
  health_interval    INTEGER NOT NULL,
  health_timeout     INTEGER NOT NULL,
  health_workers     INTEGER NOT NULL
);
```

And append one entry to the `migrations` slice, so databases created before this change get the table too. `CREATE TABLE IF NOT EXISTS` is safe to run on a fresh database, but the migration only runs on an old one:

```go
var migrations = []string{
	`ALTER TABLE services ADD COLUMN proxy_address TEXT NOT NULL DEFAULT '';
	 ALTER TABLE services ADD COLUMN route_via_proxy INTEGER NOT NULL DEFAULT 0;`,
	`CREATE TABLE IF NOT EXISTS settings (
	   id                 INTEGER PRIMARY KEY CHECK (id = 1),
	   private_domain     TEXT NOT NULL,
	   reverse_zones      TEXT NOT NULL,
	   upstreams          TEXT NOT NULL,
	   allow_query        TEXT NOT NULL,
	   allow_tailscale    INTEGER NOT NULL,
	   ttl                INTEGER NOT NULL,
	   cache_min_ttl      INTEGER NOT NULL,
	   cache_max_ttl      INTEGER NOT NULL,
	   negative_max_ttl   INTEGER NOT NULL,
	   cache_entries      INTEGER NOT NULL,
	   log_queries        INTEGER NOT NULL,
	   log_client_ip      INTEGER NOT NULL,
	   dhcp_lease_file    TEXT NOT NULL,
	   discovery_interval INTEGER NOT NULL,
	   health_interval    INTEGER NOT NULL,
	   health_timeout     INTEGER NOT NULL,
	   health_workers     INTEGER NOT NULL
	 );`,
}
```

- [ ] **Step 5: Implement the accessors**

Create `internal/store/settings.go`:

```go
package store

import (
	"database/sql"
	"errors"
	"strings"
)

// The three list columns are newline-separated text. They are always read and
// written whole and their order is positional, so a child table would buy only
// joins.
// ponytail: split into settings_list(kind, ord, value) if a per-entry edit
// (reorder one upstream, delete one prefix) ever appears in the UI.
func packList(v []string) string { return strings.Join(v, "\n") }

func unpackList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// Settings returns the stored settings. The bool is false when no row exists,
// which is how a first run knows to seed from the config file.
func (s *Store) Settings() (Settings, bool, error) {
	var v Settings
	var rz, up, aq string
	err := s.db.QueryRow(`
SELECT private_domain, reverse_zones, upstreams, allow_query, allow_tailscale,
       ttl, cache_min_ttl, cache_max_ttl, negative_max_ttl, cache_entries,
       log_queries, log_client_ip, dhcp_lease_file, discovery_interval,
       health_interval, health_timeout, health_workers
FROM settings WHERE id = 1`).Scan(
		&v.PrivateDomain, &rz, &up, &aq, &v.AllowTailscale,
		&v.TTL, &v.CacheMinTTL, &v.CacheMaxTTL, &v.NegativeMaxTTL, &v.CacheEntries,
		&v.LogQueries, &v.LogClientIP, &v.DHCPLeaseFile, &v.DiscoveryInterval,
		&v.HealthInterval, &v.HealthTimeout, &v.HealthWorkers)
	if errors.Is(err, sql.ErrNoRows) {
		return Settings{}, false, nil
	}
	if err != nil {
		return Settings{}, false, err
	}
	v.ReverseZones, v.Upstreams, v.AllowQuery = unpackList(rz), unpackList(up), unpackList(aq)
	return v, true, nil
}

// PutSettings writes the single row. Callers validate first: this is storage,
// not policy.
func (s *Store) PutSettings(v Settings) error {
	_, err := s.db.Exec(`
INSERT INTO settings (id, private_domain, reverse_zones, upstreams, allow_query,
  allow_tailscale, ttl, cache_min_ttl, cache_max_ttl, negative_max_ttl,
  cache_entries, log_queries, log_client_ip, dhcp_lease_file,
  discovery_interval, health_interval, health_timeout, health_workers)
VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  private_domain=excluded.private_domain, reverse_zones=excluded.reverse_zones,
  upstreams=excluded.upstreams, allow_query=excluded.allow_query,
  allow_tailscale=excluded.allow_tailscale, ttl=excluded.ttl,
  cache_min_ttl=excluded.cache_min_ttl, cache_max_ttl=excluded.cache_max_ttl,
  negative_max_ttl=excluded.negative_max_ttl, cache_entries=excluded.cache_entries,
  log_queries=excluded.log_queries, log_client_ip=excluded.log_client_ip,
  dhcp_lease_file=excluded.dhcp_lease_file,
  discovery_interval=excluded.discovery_interval,
  health_interval=excluded.health_interval, health_timeout=excluded.health_timeout,
  health_workers=excluded.health_workers`,
		v.PrivateDomain, packList(v.ReverseZones), packList(v.Upstreams),
		packList(v.AllowQuery), v.AllowTailscale, v.TTL, v.CacheMinTTL,
		v.CacheMaxTTL, v.NegativeMaxTTL, v.CacheEntries, v.LogQueries,
		v.LogClientIP, v.DHCPLeaseFile, v.DiscoveryInterval, v.HealthInterval,
		v.HealthTimeout, v.HealthWorkers)
	return err
}
```

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/store/ -race -v`
Expected: PASS, including the pre-existing store tests.

- [ ] **Step 7: Verify the migration lands on an old database**

Add to `internal/store/settings_test.go`:

```go
// A database created before the settings table must gain it on the next Open,
// not fail and not wedge every future Open.
func TestSettingsMigrationOnOldDatabase(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/old.db"

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// A minimal pre-settings database: schema version 1, no settings table.
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE settings; PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a pre-settings database: %v", err)
	}
	defer st.Close()
	if _, _, err := st.Settings(); err != nil {
		t.Fatalf("settings table missing after migration: %v", err)
	}
}
```

Add `"database/sql"` and the blank sqlite driver import to the test file's imports if they are not already there.

Run: `go test ./internal/store/ -run TestSettingsMigration -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/store/
git commit -m "feat(store): add the settings table

Settings that can live in the database rather than the config file get one
singleton row, following blacklist_settings. The three ordered lists are
newline-separated text: they are always read and written whole."
```

---

### Task 2: Validation rules

**Files:**
- Create: `internal/settings/validate.go`
- Test: `internal/settings/validate_test.go`

**Interfaces:**
- Consumes: `store.Settings` from Task 1.
- Produces:
  - `func Validate(v store.Settings, confirmPublic string) error`
  - `var ErrPublicNotConfirmed = errors.New(...)`
  - `type FieldError struct { Field, Msg string }` with `Error() string`, so the API and the form can both report which input was wrong

- [ ] **Step 1: Write the failing test**

Create `internal/settings/validate_test.go`:

```go
package settings

import (
	"errors"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// valid is a settings value every test starts from, so each case changes
// exactly one thing and the failure names itself.
func valid() store.Settings {
	return store.Settings{
		PrivateDomain:     "home.arpa",
		ReverseZones:      []string{"192.168.1.0/24"},
		Upstreams:         []string{"tls://1.1.1.1:853"},
		AllowQuery:        []string{"192.168.0.0/16"},
		TTL:               60,
		CacheMinTTL:       5,
		CacheMaxTTL:       3600,
		NegativeMaxTTL:    300,
		CacheEntries:      10000,
		DiscoveryInterval: 30,
		HealthInterval:    30,
		HealthTimeout:     5,
		HealthWorkers:     8,
	}
}

func TestValidateAcceptsDefaults(t *testing.T) {
	if err := Validate(valid(), ""); err != nil {
		t.Fatalf("the shipped defaults must validate: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*store.Settings)
		field string
	}{
		{"empty private domain", func(s *store.Settings) { s.PrivateDomain = "" }, "private_domain"},
		{"private domain is not a name", func(s *store.Settings) { s.PrivateDomain = "not a domain" }, "private_domain"},
		{"unparseable reverse zone", func(s *store.Settings) { s.ReverseZones = []string{"192.168.1.0"} }, "reverse_zones"},
		{"no upstreams", func(s *store.Settings) { s.Upstreams = nil }, "upstreams"},
		{"unparseable upstream", func(s *store.Settings) { s.Upstreams = []string{"tls://example.com"} }, "upstreams"},
		{"unparseable allow_query", func(s *store.Settings) { s.AllowQuery = []string{"192.168.0.1"} }, "allow_query"},
		// Default-closed: an empty allow list refuses every query, which is a
		// server that silently stops working.
		{"empty allow_query", func(s *store.Settings) { s.AllowQuery = nil }, "allow_query"},
		{"zero ttl", func(s *store.Settings) { s.TTL = 0 }, "ttl"},
		{"min ttl above max", func(s *store.Settings) { s.CacheMinTTL = 4000 }, "cache_min_ttl"},
		{"zero cache entries", func(s *store.Settings) { s.CacheEntries = 0 }, "cache_entries"},
		{"zero negative max ttl", func(s *store.Settings) { s.NegativeMaxTTL = 0 }, "negative_max_ttl"},
		{"zero discovery interval", func(s *store.Settings) { s.DiscoveryInterval = 0 }, "discovery.interval"},
		{"no health workers", func(s *store.Settings) { s.HealthWorkers = 0 }, "health.workers"},
		// A probe that outlives its own cycle stacks up forever.
		{"health timeout not below interval", func(s *store.Settings) { s.HealthTimeout = 30 }, "health.timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := valid()
			tc.mut(&v)
			err := Validate(v, "")
			if err == nil {
				t.Fatal("accepted a value it must reject")
			}
			var fe FieldError
			if !errors.As(err, &fe) {
				t.Fatalf("error is not a FieldError, so no input can be highlighted: %v", err)
			}
			if fe.Field != tc.field {
				t.Errorf("blamed %q, want %q", fe.Field, tc.field)
			}
		})
	}
}

// A relative lease path would resolve against whatever directory the process
// happened to start in, which differs between the host and the container.
func TestValidateRejectsRelativeLeasePath(t *testing.T) {
	v := valid()
	v.DHCPLeaseFile = "leases"
	err := Validate(v, "")
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative lease path accepted: %v", err)
	}
}

// An empty lease path is how discovery stays off, and must remain valid.
func TestValidateAllowsDiscoveryOff(t *testing.T) {
	v := valid()
	v.DHCPLeaseFile = ""
	if err := Validate(v, ""); err != nil {
		t.Fatalf("discovery off must validate: %v", err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/settings/ -v`
Expected: FAIL — the package does not exist.

- [ ] **Step 3: Implement**

Create `internal/settings/validate.go`:

```go
// Package settings owns the process configuration that lives in the database.
// It holds the live snapshot the runtime reads and the single path by which
// that snapshot changes.
package settings

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/upstream"
)

// FieldError names the input that was wrong, so the API and the form both
// report the same field rather than a wall of prose.
type FieldError struct {
	Field string
	Msg   string
}

func (e FieldError) Error() string { return e.Field + ": " + e.Msg }

func bad(field, format string, args ...any) error {
	return FieldError{Field: field, Msg: fmt.Sprintf(format, args...)}
}

// Validate reports whether v may be stored. Both the first-run seed and every
// later write call it, so nothing can reach the database that could not have
// been in the config file.
func Validate(v store.Settings, confirmPublic string) error {
	if strings.TrimSpace(v.PrivateDomain) == "" {
		return bad("private_domain", "must not be empty")
	}
	if _, ok := dns.IsDomainName(v.PrivateDomain); !ok {
		return bad("private_domain", "%q is not a valid domain name", v.PrivateDomain)
	}
	for _, z := range v.ReverseZones {
		if _, err := netip.ParsePrefix(z); err != nil {
			return bad("reverse_zones", "%q is not a CIDR prefix", z)
		}
	}
	if len(v.Upstreams) == 0 {
		return bad("upstreams", "at least one upstream is required")
	}
	if _, err := upstream.ParseAll(v.Upstreams); err != nil {
		return bad("upstreams", "%s", err)
	}
	if err := validateAllowQuery(v.AllowQuery, confirmPublic); err != nil {
		return err
	}
	positives := []struct {
		field string
		val   int
	}{
		{"ttl", v.TTL},
		{"cache_min_ttl", v.CacheMinTTL},
		{"cache_max_ttl", v.CacheMaxTTL},
		{"negative_max_ttl", v.NegativeMaxTTL},
		{"cache_entries", v.CacheEntries},
		{"discovery.interval", v.DiscoveryInterval},
		{"health.interval", v.HealthInterval},
		{"health.timeout", v.HealthTimeout},
		{"health.workers", v.HealthWorkers},
	}
	for _, p := range positives {
		if p.val < 1 {
			return bad(p.field, "must be at least 1")
		}
	}
	if v.CacheMinTTL > v.CacheMaxTTL {
		return bad("cache_min_ttl", "must not exceed cache_max_ttl (%d)", v.CacheMaxTTL)
	}
	if v.HealthTimeout >= v.HealthInterval {
		return bad("health.timeout", "must be below health.interval (%d), or probes outlive their own cycle", v.HealthInterval)
	}
	if v.DHCPLeaseFile != "" && !filepath.IsAbs(v.DHCPLeaseFile) {
		return bad("discovery.dhcp_lease_file", "must be an absolute path")
	}
	return nil
}
```

`validateAllowQuery` is written in Task 3. To keep this task compiling and its tests meaningful, add the permissive placeholder now and replace it there:

```go
// Replaced in the next commit by the public-range guardrail.
func validateAllowQuery(list []string, _ string) error {
	if len(list) == 0 {
		return bad("allow_query", "must list at least one range, or every query is refused")
	}
	for _, c := range list {
		if _, err := netip.ParsePrefix(c); err != nil {
			return bad("allow_query", "%q is not a CIDR prefix", c)
		}
	}
	return nil
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/settings/ -race -v`
Expected: PASS. `TestValidateRejects` covers every case above.

- [ ] **Step 5: Commit**

```bash
git add internal/settings/
git commit -m "feat(settings): validate settings in one place

Both the first-run seed and every later write go through Validate, so
nothing reaches the database that could not have been in the config file.
Errors name the field so the API and the form blame the same input."
```

---

### Task 3: The allow_query guardrail

**Files:**
- Modify: `internal/settings/validate.go`
- Test: `internal/settings/validate_test.go`

**Interfaces:**
- Consumes: `FieldError`, `bad` from Task 2.
- Produces:
  - `func IsPrivatePrefix(p netip.Prefix) bool`
  - `func PublicPrefixes(list []string) []string` — the non-private entries of an allow list, for the standing warning banner
  - `validateAllowQuery` now enforcing the confirmation

- [ ] **Step 1: Write the failing test**

Append to `internal/settings/validate_test.go`:

```go
// allow_query is what stops KyDNS being an open resolver, so widening it must
// be impossible to do by accident.
func TestValidateRejectsPublicPrefixWithoutConfirmation(t *testing.T) {
	v := valid()
	v.AllowQuery = []string{"192.168.0.0/16", "0.0.0.0/0"}

	err := Validate(v, "")
	if err == nil {
		t.Fatal("a public range was accepted with no confirmation")
	}
	var fe FieldError
	if !errors.As(err, &fe) || fe.Field != "allow_query" {
		t.Fatalf("wrong field blamed: %v", err)
	}
	if !strings.Contains(err.Error(), "0.0.0.0/0") {
		t.Errorf("the message does not name the offending prefix: %v", err)
	}
}

// The confirmation is the prefix itself, so muscle memory cannot supply it and
// a copy-pasted API body cannot carry a blanket override.
func TestValidateAcceptsPublicPrefixWithMatchingConfirmation(t *testing.T) {
	v := valid()
	v.AllowQuery = []string{"192.168.0.0/16", "0.0.0.0/0"}
	if err := Validate(v, "0.0.0.0/0"); err != nil {
		t.Fatalf("a confirmed public range must be accepted: %v", err)
	}
}

func TestValidateRejectsMismatchedConfirmation(t *testing.T) {
	v := valid()
	v.AllowQuery = []string{"8.8.8.0/24"}
	if err := Validate(v, "0.0.0.0/0"); err == nil {
		t.Fatal("a confirmation for a different prefix was accepted")
	}
}

// Confirming one public prefix must not smuggle a second one through.
func TestValidateRejectsSecondUnconfirmedPublicPrefix(t *testing.T) {
	v := valid()
	v.AllowQuery = []string{"0.0.0.0/0", "8.8.8.0/24"}
	err := Validate(v, "0.0.0.0/0")
	if err == nil || !strings.Contains(err.Error(), "8.8.8.0/24") {
		t.Fatalf("the unconfirmed second prefix passed: %v", err)
	}
}

func TestPrivatePrefixesNeedNoConfirmation(t *testing.T) {
	for _, c := range []string{
		"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12",
		"192.168.0.0/16", "169.254.0.0/16", "fe80::/10", "fc00::/7",
		"100.64.0.0/10", "192.168.1.128/25",
	} {
		v := valid()
		v.AllowQuery = []string{c}
		if err := Validate(v, ""); err != nil {
			t.Errorf("%s is a private range and must need no confirmation: %v", c, err)
		}
	}
}

func TestPublicPrefixes(t *testing.T) {
	got := PublicPrefixes([]string{"192.168.0.0/16", "0.0.0.0/0", "junk", "8.8.8.8/32"})
	want := []string{"0.0.0.0/0", "8.8.8.8/32"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/settings/ -run 'Public|Confirm|Private' -v`
Expected: FAIL — `PublicPrefixes` undefined, and the permissive placeholder accepts `0.0.0.0/0`.

- [ ] **Step 3: Implement**

Replace the placeholder `validateAllowQuery` in `internal/settings/validate.go`:

```go
// privateRanges are the prefixes a homelab resolver is expected to serve:
// loopback, RFC1918, link-local, ULA, and the CGNAT range Tailscale uses.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("100.64.0.0/10"),
}

// IsPrivatePrefix reports whether p is wholly inside a range a homelab
// resolver is expected to serve. Containment, not overlap: 0.0.0.0/0 overlaps
// every private range without being one.
func IsPrivatePrefix(p netip.Prefix) bool {
	p = p.Masked()
	for _, r := range privateRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// PublicPrefixes returns the entries of an allow list that reach beyond the
// private ranges. Unparseable entries are skipped: Validate rejects those with
// a better message. Callers use this for the standing exposure warning.
func PublicPrefixes(list []string) []string {
	var out []string
	for _, c := range list {
		p, err := netip.ParsePrefix(c)
		if err != nil || IsPrivatePrefix(p) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// validateAllowQuery enforces the guardrail: a prefix outside the private
// ranges is refused unless the same request retypes it in confirmPublic.
func validateAllowQuery(list []string, confirmPublic string) error {
	if len(list) == 0 {
		return bad("allow_query", "must list at least one range, or every query is refused")
	}
	for _, c := range list {
		if _, err := netip.ParsePrefix(c); err != nil {
			return bad("allow_query", "%q is not a CIDR prefix", c)
		}
	}
	for _, c := range PublicPrefixes(list) {
		if c == confirmPublic {
			continue
		}
		return bad("allow_query",
			"%s reaches beyond your LAN and would make KyDNS an open resolver. "+
				"Retype it in the confirmation field to allow it anyway.", c)
	}
	return nil
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/settings/ -race -v`
Expected: PASS, all guardrail cases included.

- [ ] **Step 5: Commit**

```bash
git add internal/settings/
git commit -m "feat(settings): refuse a public allow_query without confirmation

A prefix outside loopback, RFC1918, ULA, link-local and CGNAT is rejected
unless the same request retypes it. Retyping the prefix rather than
ticking a box means the confirmation cannot be muscle memory, and a
copy-pasted API body cannot carry a blanket override."
```

---

### Task 4: The snapshot

**Files:**
- Create: `internal/settings/settings.go`
- Test: `internal/settings/settings_test.go`

**Interfaces:**
- Consumes: `Validate` from Tasks 2 and 3, `store.Settings` from Task 1.
- Produces:
  - `type Snapshot struct { Raw store.Settings; AllowQuery []netip.Prefix; ReverseZones []netip.Prefix; Upstreams []upstream.Upstream }`
  - `func Build(v store.Settings) (*Snapshot, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/settings/settings_test.go`:

```go
package settings

import (
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func TestBuildParsesEverything(t *testing.T) {
	v := valid()
	v.ReverseZones = []string{"192.168.1.0/24"}
	v.Upstreams = []string{"tls://1.1.1.1:853", "udp://192.168.1.1:53"}

	snap, err := Build(v)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(snap.Upstreams) != 2 {
		t.Fatalf("got %d upstreams, want 2", len(snap.Upstreams))
	}
	// Upstreams are tried in order, so Build must not reorder them.
	if snap.Upstreams[0].String() != "tls://1.1.1.1:853" {
		t.Errorf("upstream order changed: %s", snap.Upstreams[0])
	}
	if len(snap.ReverseZones) != 1 || snap.ReverseZones[0].String() != "192.168.1.0/24" {
		t.Errorf("reverse zones: %v", snap.ReverseZones)
	}
	if len(snap.AllowQuery) != 1 {
		t.Fatalf("allow_query: %v", snap.AllowQuery)
	}
}

// AllowTailscale is a checkbox, not a range the operator types. The snapshot is
// what the ACL reads, so the range has to be in it.
func TestBuildAddsTailscaleRange(t *testing.T) {
	v := valid()
	v.AllowTailscale = true
	snap, err := Build(v)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range snap.AllowQuery {
		if p.String() == "100.64.0.0/10" {
			found = true
		}
	}
	if !found {
		t.Errorf("allow_tailscale on, but CGNAT is not in the ACL: %v", snap.AllowQuery)
	}

	v.AllowTailscale = false
	snap, err = Build(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range snap.AllowQuery {
		if p.String() == "100.64.0.0/10" {
			t.Error("allow_tailscale off, but CGNAT is in the ACL")
		}
	}
}

// Build is the only fallible step of an apply. It must fail before anything is
// swapped, never halfway through.
func TestBuildFailsWholeOnBadUpstream(t *testing.T) {
	v := valid()
	v.Upstreams = []string{"tls://1.1.1.1:853", "tls://example.com:853"}
	if _, err := Build(v); err == nil {
		t.Fatal("Build accepted a hostname upstream; it must fail before any swap")
	}
}

func TestBuildKeepsRaw(t *testing.T) {
	v := valid()
	v.TTL = 120
	snap, err := Build(v)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Raw.TTL != 120 {
		t.Errorf("Raw.TTL is %d, want 120", snap.Raw.TTL)
	}
	if _, ok := any(snap.Raw).(store.Settings); !ok {
		t.Error("Raw must be the stored settings verbatim")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/settings/ -run TestBuild -v`
Expected: FAIL — `Build` undefined.

- [ ] **Step 3: Implement**

Create `internal/settings/settings.go`:

```go
package settings

import (
	"net/netip"

	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/upstream"
)

// TailscaleCGNAT is the range AllowTailscale adds to the ACL.
const TailscaleCGNAT = "100.64.0.0/10"

// Snapshot is the parsed, immutable form of the settings. Building it is the
// only fallible part of applying a change, so every swap that follows is
// infallible.
type Snapshot struct {
	Raw          store.Settings
	AllowQuery   []netip.Prefix
	ReverseZones []netip.Prefix
	Upstreams    []upstream.Upstream
}

// Build parses v. It is all-or-nothing: any error returns before a caller has
// swapped anything into the running server.
func Build(v store.Settings) (*Snapshot, error) {
	s := &Snapshot{Raw: v}

	allow := append([]string(nil), v.AllowQuery...)
	if v.AllowTailscale {
		allow = append(allow, TailscaleCGNAT)
	}
	for _, c := range allow {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, bad("allow_query", "%q is not a CIDR prefix", c)
		}
		s.AllowQuery = append(s.AllowQuery, p.Masked())
	}
	for _, c := range v.ReverseZones {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, bad("reverse_zones", "%q is not a CIDR prefix", c)
		}
		s.ReverseZones = append(s.ReverseZones, p.Masked())
	}
	ups, err := upstream.NewAll(v.Upstreams, 2*upstreamTimeout)
	if err != nil {
		return nil, bad("upstreams", "%s", err)
	}
	s.Upstreams = ups
	return s, nil
}
```

Check the constant `upstreamTimeout` does not already exist elsewhere; `internal/app/serve.go` currently passes `2*time.Second` to `upstream.NewAll`. Declare it in this file and use the same value:

```go
// upstreamTimeout matches what the forwarder allows per query.
const upstreamTimeout = time.Second
```

with `"time"` imported, so `2*upstreamTimeout` is the `2*time.Second` the process used before.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/settings/ -race -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/settings/
git commit -m "feat(settings): parse settings into an immutable snapshot

Build is the only fallible step of applying a change. Everything after it
is an atomic pointer store, so a bad value cannot leave the running server
half-configured."
```

---

### Task 5: Holder and Service

**Files:**
- Modify: `internal/settings/settings.go`
- Test: `internal/settings/settings_test.go`

**Interfaces:**
- Consumes: `Build`, `Validate`.
- Produces:
  - `type Source func() (store.Settings, error)`
  - `type Holder struct{...}`, `func NewHolder(Source) *Holder`, `(*Holder).Rebuild() error`, `(*Holder).Current() *Snapshot`
  - `type Writer interface { PutSettings(store.Settings) error }`
  - `type Service struct{...}`, `func NewService(w Writer, h *Holder, onApply func(*Snapshot)) *Service`
  - `(*Service).Get() (store.Settings, error)`, `(*Service).Set(v store.Settings, confirmPublic string) error`

- [ ] **Step 1: Write the failing test**

Append to `internal/settings/settings_test.go`:

```go
// fakeWriter is the store slice this package needs. Depending on an interface
// keeps the test a struct literal, matching health.Lister.
type fakeWriter struct {
	cur     store.Settings
	writes  int
	failErr error
}

func (f *fakeWriter) PutSettings(v store.Settings) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.cur = v
	f.writes++
	return nil
}

func newTestService(t *testing.T) (*fakeWriter, *Service, *[]*Snapshot) {
	t.Helper()
	w := &fakeWriter{cur: valid()}
	h := NewHolder(func() (store.Settings, error) { return w.cur, nil })
	if err := h.Rebuild(); err != nil {
		t.Fatalf("initial rebuild: %v", err)
	}
	var applied []*Snapshot
	svc := NewService(w, h, func(s *Snapshot) { applied = append(applied, s) })
	return w, svc, &applied
}

func TestServiceSetPersistsRebuildsAndApplies(t *testing.T) {
	w, svc, applied := newTestService(t)

	v := valid()
	v.TTL = 120
	if err := svc.Set(v, ""); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if w.cur.TTL != 120 {
		t.Errorf("not persisted: %d", w.cur.TTL)
	}
	if len(*applied) != 1 || (*applied)[0].Raw.TTL != 120 {
		t.Fatalf("apply did not see the new snapshot: %v", *applied)
	}
	if svc.Holder().Current().Raw.TTL != 120 {
		t.Error("the holder still serves the old snapshot")
	}
}

// A rejected save must leave both the database and the running server alone.
func TestServiceSetRejectsBeforeWriting(t *testing.T) {
	w, svc, applied := newTestService(t)
	before := w.writes

	v := valid()
	v.AllowQuery = []string{"0.0.0.0/0"}
	if err := svc.Set(v, ""); err == nil {
		t.Fatal("an unconfirmed public range was saved")
	}
	if w.writes != before {
		t.Error("a rejected save still wrote to the database")
	}
	if len(*applied) != 0 {
		t.Error("a rejected save still applied to the running server")
	}
}

// A store failure must not apply either: the running server and the database
// have to agree.
func TestServiceSetDoesNotApplyWhenTheWriteFails(t *testing.T) {
	w, svc, applied := newTestService(t)
	w.failErr = errors.New("disk full")

	v := valid()
	v.TTL = 120
	if err := svc.Set(v, ""); err == nil {
		t.Fatal("Set reported success after the write failed")
	}
	if len(*applied) != 0 {
		t.Error("applied a change that was never stored")
	}
}

// Concurrent reads of the snapshot while it is being replaced must not tear.
// Run with -race for this to mean anything.
func TestHolderConcurrentRebuild(t *testing.T) {
	w := &fakeWriter{cur: valid()}
	h := NewHolder(func() (store.Settings, error) { return w.cur, nil })
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			if h.Current() == nil {
				t.Error("Current returned nil after the first build")
				return
			}
		}
	}()
	for i := 0; i < 500; i++ {
		if err := h.Rebuild(); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}
```

Add `"errors"` to the test file's imports.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/settings/ -run 'TestService|TestHolder' -v`
Expected: FAIL — `NewHolder`, `NewService` undefined.

- [ ] **Step 3: Implement**

Append to `internal/settings/settings.go`:

```go
// Source pulls the stored settings. It returns an error rather than partial
// data, so a transient store failure cannot empty the running configuration.
type Source func() (store.Settings, error)

// Holder owns the live snapshot. Readers on the DNS hot path load a pointer;
// writers call Rebuild, which builds fully before swapping.
type Holder struct {
	src Source
	cur atomic.Pointer[Snapshot]

	// rebuildMu serializes Rebuild so a slower concurrent rebuild cannot
	// publish a stale snapshot after a faster, later one.
	rebuildMu sync.Mutex
}

func NewHolder(src Source) *Holder { return &Holder{src: src} }

// Rebuild pulls fresh settings, builds a complete snapshot, and swaps it in.
// Any error returns before the swap.
func (h *Holder) Rebuild() error {
	h.rebuildMu.Lock()
	defer h.rebuildMu.Unlock()
	v, err := h.src()
	if err != nil {
		return err
	}
	snap, err := Build(v)
	if err != nil {
		return err
	}
	h.cur.Store(snap)
	return nil
}

// Current returns the live snapshot, or nil before the first successful build.
func (h *Holder) Current() *Snapshot { return h.cur.Load() }

// Writer is the store slice this package needs.
type Writer interface {
	PutSettings(store.Settings) error
}

// Service is the single write path for settings: validate, persist, rebuild,
// apply. onApply is injected so this package never imports the runtime.
type Service struct {
	w       Writer
	h       *Holder
	onApply func(*Snapshot)

	// writeMu makes validate-persist-rebuild-apply atomic against a second
	// concurrent Set, so two saves cannot interleave into a state neither asked
	// for.
	writeMu sync.Mutex
}

func NewService(w Writer, h *Holder, onApply func(*Snapshot)) *Service {
	if onApply == nil {
		onApply = func(*Snapshot) {}
	}
	return &Service{w: w, h: h, onApply: onApply}
}

func (s *Service) Holder() *Holder { return s.h }

// Get returns the settings as stored.
func (s *Service) Get() (store.Settings, error) {
	if snap := s.h.Current(); snap != nil {
		return snap.Raw, nil
	}
	return store.Settings{}, errors.New("settings are not loaded yet")
}

// Set validates, persists, rebuilds the snapshot, then applies it. Nothing is
// stored or applied unless every step before it succeeded.
func (s *Service) Set(v store.Settings, confirmPublic string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if err := Validate(v, confirmPublic); err != nil {
		return err
	}
	// Build before the write, so an input that validates but cannot be
	// constructed never reaches the database.
	if _, err := Build(v); err != nil {
		return err
	}
	if err := s.w.PutSettings(v); err != nil {
		return err
	}
	if err := s.h.Rebuild(); err != nil {
		return err
	}
	s.onApply(s.h.Current())
	return nil
}
```

Add `"errors"`, `"sync"`, and `"sync/atomic"` to the file's imports.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/settings/ -race -v`
Expected: PASS, including `TestHolderConcurrentRebuild` under the race detector.

- [ ] **Step 5: Commit**

```bash
git add internal/settings/
git commit -m "feat(settings): hold the live snapshot behind one write path

Holder mirrors policy.Holder and zone.Holder: readers load a pointer,
writers build fully before swapping. Service is the only way settings
change - validate, persist, rebuild, apply - and stops at the first
failure, so the database and the running server cannot disagree."
```

---

### Task 6: Seed from the config file on first run

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: `store.Settings` from Task 1.
- Produces: `func (c *Config) SeedSettings() store.Settings`

- [ ] **Step 1: Write the failing test**

Append to `internal/config/config_test.go`:

```go
// The file seeds the database on first run, so every moved key has to survive
// the trip. A key missing here is a setting that silently reverts to its
// default the first time an operator upgrades.
func TestSeedSettingsCarriesEveryMovedKey(t *testing.T) {
	path := writeConfig(t, `
data_dir: /tmp/kydns
dns:
  private_domain: lab.example
  reverse_zones: ["192.168.1.0/24"]
  upstreams: ["tls://9.9.9.9:853"]
  allow_query: ["192.168.0.0/16"]
  allow_tailscale: true
  ttl: 90
  cache_min_ttl: 10
  cache_max_ttl: 1800
  negative_max_ttl: 120
  cache_entries: 500
  log_queries: true
  log_client_ip: true
discovery:
  dhcp_lease_file: /var/lib/misc/dnsmasq.leases
  interval: 15
health:
  interval: 45
  timeout: 3
  workers: 4
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := c.SeedSettings()
	want := store.Settings{
		PrivateDomain:     "lab.example",
		ReverseZones:      []string{"192.168.1.0/24"},
		Upstreams:         []string{"tls://9.9.9.9:853"},
		AllowQuery:        []string{"192.168.0.0/16"},
		AllowTailscale:    true,
		TTL:               90,
		CacheMinTTL:       10,
		CacheMaxTTL:       1800,
		NegativeMaxTTL:    120,
		CacheEntries:      500,
		LogQueries:        true,
		LogClientIP:       true,
		DHCPLeaseFile:     "/var/lib/misc/dnsmasq.leases",
		DiscoveryInterval: 15,
		HealthInterval:    45,
		HealthTimeout:     3,
		HealthWorkers:     4,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("seed differs\n got %+v\nwant %+v", got, want)
	}
}

// A file with nothing but data_dir must seed the same defaults the code
// applies, so a bare install and a documented install agree.
func TestSeedSettingsUsesDefaults(t *testing.T) {
	c, err := Load(writeConfig(t, "data_dir: /tmp/kydns\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := c.SeedSettings()
	if got.PrivateDomain != "home.arpa" || got.TTL != 60 || got.HealthWorkers != 8 {
		t.Errorf("defaults did not reach the seed: %+v", got)
	}
	if len(got.Upstreams) == 0 || len(got.AllowQuery) == 0 {
		t.Error("the seeded upstreams or ACL are empty, which would refuse every query")
	}
}
```

Check the name of the existing helper that writes a temporary config file: run `grep -n "func writeConfig\|func tempConfig\|WriteFile" internal/config/config_test.go | head`, and use whatever is already there. Add `"reflect"` and the store import if missing.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/config/ -run TestSeedSettings -v`
Expected: FAIL — `SeedSettings` undefined.

- [ ] **Step 3: Implement**

Append to `internal/config/config.go`:

```go
// SeedSettings is the config file's contribution to a fresh database: every
// key that has moved into the store, with defaults already applied. It is read
// once, on the first run. After that the database owns these values and edits
// to the file do nothing.
func (c *Config) SeedSettings() store.Settings {
	return store.Settings{
		PrivateDomain:     c.DNS.PrivateDomain,
		ReverseZones:      append([]string(nil), c.DNS.ReverseZones...),
		Upstreams:         append([]string(nil), c.DNS.Upstreams...),
		AllowQuery:        append([]string(nil), c.DNS.AllowQuery...),
		AllowTailscale:    c.DNS.AllowTailscale,
		TTL:               c.DNS.TTL,
		CacheMinTTL:       c.DNS.CacheMinTTL,
		CacheMaxTTL:       c.DNS.CacheMaxTTL,
		NegativeMaxTTL:    c.DNS.NegativeMaxTTL,
		CacheEntries:      c.DNS.CacheEntries,
		LogQueries:        c.DNS.LogQueries,
		LogClientIP:       c.DNS.LogClientIP,
		DHCPLeaseFile:     c.Discovery.DHCPLeaseFile,
		DiscoveryInterval: c.Discovery.Interval,
		HealthInterval:    c.Health.Interval,
		HealthTimeout:     c.Health.Timeout,
		HealthWorkers:     c.Health.Workers,
	}
}
```

Add the store import. `internal/store` must not import `internal/config`, or this creates a cycle — check with `go build ./...` after the edit.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/config/ -race -v && go build ./...`
Expected: PASS, and no import cycle.

- [ ] **Step 5: Commit**

```bash
git add internal/config/
git commit -m "feat(config): map the config file onto the seeded settings

The file seeds the database once, on the first run. Every key that has
moved is carried across with its defaults already applied, so a bare
install and a fully written config agree on what they mean."
```

---

### Task 7: Live ACL replacement

**Files:**
- Modify: `internal/dnsserver/acl.go`
- Test: `internal/dnsserver/acl_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `func (a *ACL) Replace(allowed []netip.Prefix)`

Note: `acl.go` currently imports `internal/config` for `config.TailscaleCGNAT`. Switch that reference to `settings.TailscaleCGNAT` from Task 4 so the constant has one home, and confirm `internal/settings` does not import `internal/dnsserver` (it does not).

- [ ] **Step 1: Write the failing test**

Append to `internal/dnsserver/acl_test.go`:

```go
func TestACLReplace(t *testing.T) {
	lan := netip.MustParsePrefix("192.168.0.0/16")
	tail := netip.MustParsePrefix("100.64.0.0/10")
	acl := NewACL([]netip.Prefix{lan})

	if !acl.Allow(netip.MustParseAddr("192.168.1.5")) {
		t.Fatal("the LAN was refused before the swap")
	}
	if acl.Allow(netip.MustParseAddr("100.64.0.1")) {
		t.Fatal("CGNAT was allowed before the swap")
	}

	acl.Replace([]netip.Prefix{lan, tail})

	if !acl.Allow(netip.MustParseAddr("100.64.0.1")) {
		t.Error("CGNAT is still refused after the swap")
	}

	// Narrowing has to work too: a mistake must be undoable without a restart.
	acl.Replace([]netip.Prefix{tail})
	if acl.Allow(netip.MustParseAddr("192.168.1.5")) {
		t.Error("the LAN is still allowed after being removed")
	}
}

// Replace must mask, exactly as NewACL does, or a host-bit-carrying prefix
// silently matches nothing.
func TestACLReplaceMasks(t *testing.T) {
	acl := NewACL(nil)
	acl.Replace([]netip.Prefix{netip.MustParsePrefix("192.168.1.99/24")})
	if !acl.Allow(netip.MustParseAddr("192.168.1.5")) {
		t.Error("an unmasked prefix did not match its own network")
	}
}

// Counters describe the process, not the current policy, so a swap must not
// reset them.
func TestACLReplaceKeepsCounters(t *testing.T) {
	acl := NewACL(nil)
	acl.Allow(netip.MustParseAddr("8.8.8.8"))
	acl.Replace([]netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")})
	if acl.Stats().Total != 1 {
		t.Errorf("refusal count reset by a swap: %d", acl.Stats().Total)
	}
}

// Readers must not tear while the list is replaced. Meaningful only with -race.
func TestACLReplaceUnderConcurrentReads(t *testing.T) {
	acl := NewACL([]netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			acl.Allow(netip.MustParseAddr("192.168.1.5"))
		}
	}()
	for i := 0; i < 2000; i++ {
		acl.Replace([]netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")})
	}
	<-done
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/dnsserver/ -run TestACLReplace -v`
Expected: FAIL — `acl.Replace undefined`.

- [ ] **Step 3: Implement**

In `internal/dnsserver/acl.go`, change the `allowed` field to an atomic pointer and route both `NewACL` and `Replace` through the same masking:

```go
type ACL struct {
	allowed   atomic.Pointer[[]netip.Prefix]
	total     atomic.Uint64
	cgnat     atomic.Uint64
	lastCGNAT atomic.Int64
	now       func() time.Time // swappable for tests
}

func NewACL(allowed []netip.Prefix) *ACL {
	a := &ACL{now: time.Now}
	a.Replace(allowed)
	return a
}

// Replace swaps the allow list. Readers on the query path load a pointer, so a
// swap never blocks a query and never shows a half-built list. Refusal
// counters describe the process and survive it.
func (a *ACL) Replace(allowed []netip.Prefix) {
	masked := make([]netip.Prefix, 0, len(allowed))
	for _, p := range allowed {
		masked = append(masked, p.Masked())
	}
	a.allowed.Store(&masked)
}
```

And in `Allow`, load once:

```go
	for _, p := range *a.allowed.Load() {
		if p.Contains(addr) {
			return true
		}
	}
```

Add `"sync/atomic"` if it is not already imported (it is). Replace the `config.TailscaleCGNAT` reference with `settings.TailscaleCGNAT` and update the import.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/dnsserver/ -race -v && go build ./...`
Expected: PASS. The existing ACL tests must still pass unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/dnsserver/acl.go internal/dnsserver/acl_test.go
git commit -m "feat(dnsserver): swap the query ACL without a restart

The allow list moves behind an atomic pointer, so a query loads it without
a lock and a change never shows a half-built list. Refusal counters
describe the process, so a swap leaves them alone."
```

---

### Task 8: Live upstream replacement

**Files:**
- Modify: `internal/dnsserver/forward.go`
- Test: `internal/dnsserver/forward_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `func (f *Forwarder) Replace(ups []upstream.Upstream)`

The subtlety: `record(i, err)` indexes into a status slice that is parallel to the upstream list. If the list is swapped mid-query, a stale index would write to the wrong entry or panic. Fix it by putting the pair in one immutable state object behind an atomic pointer — `Resolve` loads the state once and passes it down, so a late write lands on the object it came from and is discarded with it.

- [ ] **Step 1: Write the failing test**

Append to `internal/dnsserver/forward_test.go`:

```go
func TestForwarderReplace(t *testing.T) {
	// stubUpstream is whatever the existing forward tests already use; reuse it
	// rather than adding a second fake. Check with:
	//   grep -n "upstream.Upstream" internal/dnsserver/forward_test.go
	a := newStubUpstream("udp://10.0.0.1:53", nil)
	b := newStubUpstream("udp://10.0.0.2:53", nil)

	f := NewForwarder([]upstream.Upstream{a}, time.Second, NewCache(10, 1, 10, 10))
	if got := f.Status(); len(got) != 1 || got[0].Spec != "udp://10.0.0.1:53" {
		t.Fatalf("status before the swap: %+v", got)
	}

	f.Replace([]upstream.Upstream{b})

	got := f.Status()
	if len(got) != 1 || got[0].Spec != "udp://10.0.0.2:53" {
		t.Fatalf("status after the swap: %+v", got)
	}
	// A fresh list has never been tried, so it must not inherit the old list's
	// errors: a stale red mark sends the operator debugging a fixed problem.
	if got[0].LastError != "" {
		t.Errorf("new upstream inherited an error: %q", got[0].LastError)
	}
}

// Queries in flight during a swap must not panic or write to the wrong status
// entry. Meaningful only with -race.
func TestForwarderReplaceUnderLoad(t *testing.T) {
	a := newStubUpstream("udp://10.0.0.1:53", nil)
	b := newStubUpstream("udp://10.0.0.2:53", errors.New("refused"))
	f := NewForwarder([]upstream.Upstream{a}, time.Second, NewCache(10, 1, 10, 10))

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			_, _ = f.Resolve(context.Background(), q, false)
		}
	}()
	for i := 0; i < 500; i++ {
		if i%2 == 0 {
			f.Replace([]upstream.Upstream{b})
		} else {
			f.Replace([]upstream.Upstream{a})
		}
		_ = f.Status()
	}
	<-done
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/dnsserver/ -run TestForwarderReplace -v`
Expected: FAIL — `f.Replace undefined`.

- [ ] **Step 3: Implement**

In `internal/dnsserver/forward.go`, introduce the state object:

```go
// fwdState pairs the upstream list with its status slice. They are only ever
// swapped together, so an in-flight query cannot record a result against an
// upstream that is no longer at that index.
type fwdState struct {
	ups []upstream.Upstream

	mu     sync.Mutex
	status []UpstreamStatus
}

type Forwarder struct {
	state   atomic.Pointer[fwdState]
	timeout time.Duration
	cache   *Cache
	group   singleflight.Group
}

func NewForwarder(ups []upstream.Upstream, timeout time.Duration, c *Cache) *Forwarder {
	f := &Forwarder{timeout: timeout, cache: c}
	f.Replace(ups)
	return f
}

// Replace swaps the upstream list. Status starts clean: the new upstreams have
// never been tried, and a stale error would send the operator after a problem
// that no longer exists.
func (f *Forwarder) Replace(ups []upstream.Upstream) {
	st := &fwdState{ups: ups, status: make([]UpstreamStatus, len(ups))}
	for i, u := range ups {
		st.status[i] = UpstreamStatus{Spec: u.String(), Secure: u.Secure()}
	}
	f.state.Store(st)
}

// Status is a snapshot for the UI, copied so callers cannot race the recorder.
func (f *Forwarder) Status() []UpstreamStatus {
	st := f.state.Load()
	st.mu.Lock()
	defer st.mu.Unlock()
	return append([]UpstreamStatus(nil), st.status...)
}

// record writes against the state the query started with. A result arriving
// after a swap lands on the retired object and is discarded with it, which is
// correct: it describes upstreams that are no longer configured.
func (st *fwdState) record(i int, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if err != nil {
		st.status[i].LastError = err.Error()
		st.status[i].LastErrAt = time.Now()
		return
	}
	st.status[i].LastError = ""
	st.status[i].LastErrAt = time.Time{}
	st.status[i].LastOKAt = time.Now()
}
```

Then update `Resolve` and `exchange` to load the state once at entry and iterate `st.ups`, calling `st.record(i, err)` instead of `f.record(i, err)`. Add `"sync/atomic"` to the imports.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/dnsserver/ -race -v`
Expected: PASS, including the existing forward tests unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/dnsserver/forward.go internal/dnsserver/forward_test.go
git commit -m "feat(dnsserver): swap upstreams without a restart

The upstream list and its status slice move into one state object behind
an atomic pointer, so a query that started before a swap records its
result against the list it actually used."
```

---

### Task 9: Live cache, TTL, reverse zones, and log flags

**Files:**
- Modify: `internal/dnsserver/cache.go`, `internal/dnsserver/server.go`, `internal/dnsserver/auth.go`
- Test: `internal/dnsserver/cache_test.go`, `internal/dnsserver/server_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `func (c *Cache) Retune(maxEntries, minTTL, maxTTL, negMaxTTL int)`
  - `func (s *Server) SetLogging(queries, clientIP bool)`
  - `func (a *Authoritative) SetTTL(ttl uint32)`
  - `func (a *Authoritative) SetReverseZones(z []netip.Prefix)`

Read `internal/dnsserver/auth.go` first to see how `TTL` and `ReverseZones` are currently declared and read; they are plain struct fields today and both are read on the query path, so both need to become atomics.

- [ ] **Step 1: Write the failing tests**

Append to `internal/dnsserver/cache_test.go`:

```go
func TestCacheRetuneShrinks(t *testing.T) {
	c := NewCache(10, 1, 3600, 300)
	for i := 0; i < 10; i++ {
		q := dns.Question{Name: fmt.Sprintf("h%d.example.", i), Qtype: dns.TypeA, Qclass: dns.ClassINET}
		m := new(dns.Msg)
		m.SetQuestion(q.Name, dns.TypeA)
		m.Answer = []dns.RR{testA(t, q.Name, 60)}
		c.Put(q, false, m)
	}
	if c.Len() != 10 {
		t.Fatalf("cache holds %d, want 10", c.Len())
	}

	// Shrinking must evict down immediately, not wait for the next insert:
	// an operator lowering this is reclaiming memory now.
	c.Retune(3, 1, 3600, 300)
	if c.Len() > 3 {
		t.Errorf("cache still holds %d after shrinking to 3", c.Len())
	}
}

func TestCacheRetuneChangesClamp(t *testing.T) {
	c := NewCache(10, 1, 3600, 300)
	q := dns.Question{Name: "a.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	m := new(dns.Msg)
	m.SetQuestion(q.Name, dns.TypeA)
	m.Answer = []dns.RR{testA(t, q.Name, 3000)}

	c.Retune(10, 1, 10, 300)
	c.Put(q, false, m)

	got, ok := c.Get(q, false)
	if !ok {
		t.Fatal("entry missing")
	}
	if got.Answer[0].Header().Ttl > 10 {
		t.Errorf("TTL %d exceeds the new maximum of 10", got.Answer[0].Header().Ttl)
	}
}
```

`testA` is a helper that builds an A record with a given TTL — check `internal/dnsserver/cache_test.go` for an existing one with `grep -n "func test" internal/dnsserver/cache_test.go` and reuse it; if there is none, add:

```go
func testA(t *testing.T, name string, ttl uint32) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN A 192.0.2.1", name, ttl))
	if err != nil {
		t.Fatal(err)
	}
	return rr
}
```

Append to `internal/dnsserver/server_test.go`:

```go
func TestSetLogging(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	// Reuse whatever the existing server tests use to build a Server; check
	// with: grep -n "dnsserver.New(\|New(Options{" internal/dnsserver/server_test.go
	s := New(Options{Holder: testHolder(t), ACL: NewACL(allPrefixes()), Logger: logger})

	s.query(t, "example.com.", "192.168.1.5")
	if buf.Len() != 0 {
		t.Fatal("a query was logged while query logging is off")
	}

	s.SetLogging(true, false)
	s.query(t, "example.com.", "192.168.1.5")
	out := buf.String()
	if out == "" {
		t.Fatal("query logging was turned on but nothing was logged")
	}
	// The client IP is a second, separate opt-in.
	if strings.Contains(out, "192.168.1.5") {
		t.Error("the client IP was logged with log_client_ip off")
	}

	buf.Reset()
	s.SetLogging(true, true)
	s.query(t, "example.com.", "192.168.1.5")
	if !strings.Contains(buf.String(), "192.168.1.5") {
		t.Error("the client IP was not logged with log_client_ip on")
	}
}
```

`s.query` stands for whatever the existing tests use to drive one query through `ServeDNS` with a given source address — find it with `grep -n "ServeDNS(" internal/dnsserver/server_test.go` and use that, rather than inventing a second harness.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/dnsserver/ -run 'Retune|SetLogging' -v`
Expected: FAIL — `Retune` and `SetLogging` undefined.

- [ ] **Step 3: Implement**

In `internal/dnsserver/cache.go` the bounds are already guarded by `c.mu`, so `Retune` takes the same lock:

```go
// Retune changes the bounds and the size limit. Shrinking evicts immediately:
// an operator lowering the entry count is reclaiming memory now, not next time
// something is cached.
func (c *Cache) Retune(maxEntries, minTTL, maxTTL, negMaxTTL int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxEntries = maxEntries
	c.minTTL, c.maxTTL, c.negMaxTTL = uint32(minTTL), uint32(maxTTL), uint32(negMaxTTL)
	for c.maxEntries > 0 && c.order.Len() > c.maxEntries {
		c.removeLocked(c.order.Back())
	}
}
```

In `internal/dnsserver/server.go`, move the two log flags out of `Options` storage and into atomics on `Server`:

```go
type Server struct {
	o           Options
	logQueries  atomic.Bool
	logClientIP atomic.Bool
	mu          sync.Mutex
	srvs        []*dns.Server
}

func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	s := &Server{o: o}
	s.SetLogging(o.LogQueries, o.LogClientIP)
	return s
}

// SetLogging changes both logging opt-ins. The client IP stays a separate
// choice from query logging: turning on one must never turn on the other.
func (s *Server) SetLogging(queries, clientIP bool) {
	s.logQueries.Store(queries)
	s.logClientIP.Store(clientIP)
}
```

Then change `logQuery` to read `s.logQueries.Load()` and `s.logClientIP.Load()` instead of `s.o.LogQueries` and `s.o.LogClientIP`. Leave the `Options` fields in place as the initial values.

In `internal/dnsserver/auth.go`, make the two live fields atomic and add setters:

```go
// SetTTL changes the TTL on authoritative answers. Answers already in flight
// keep the value they started with, which is one query's worth of staleness.
func (a *Authoritative) SetTTL(ttl uint32) { a.ttl.Store(ttl) }

// SetReverseZones changes which networks get derived PTR records.
func (a *Authoritative) SetReverseZones(z []netip.Prefix) {
	masked := make([]netip.Prefix, 0, len(z))
	for _, p := range z {
		masked = append(masked, p.Masked())
	}
	a.reverseZones.Store(&masked)
}
```

`Authoritative` is currently constructed as a struct literal in `internal/app/serve.go` with exported `Zone`, `TTL` and `ReverseZones` fields. Converting those to unexported atomics means adding a constructor — `func NewAuthoritative(zone string, ttl uint32, reverse []netip.Prefix) *Authoritative` — and updating that call site and every test that builds one. `Zone` stays a plain field: `private_domain` is restart-required.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/dnsserver/ -race -v && go build ./...`
Expected: PASS. Fix the `Authoritative` literals the compiler points at.

- [ ] **Step 5: Commit**

```bash
git add internal/dnsserver/
git commit -m "feat(dnsserver): retune the cache and the log flags at runtime

Shrinking the cache evicts immediately rather than waiting for the next
insert. The two logging opt-ins become atomics and keep their independence:
turning on query logging still does not record who asked."
```

---

### Task 10: Live health and discovery intervals

**Files:**
- Modify: `internal/health/checker.go`, `internal/discovery/poller.go`
- Test: `internal/health/checker_test.go`, `internal/discovery/poller_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `func (c *Checker) Reconfigure(interval, timeout time.Duration, workers int)`
  - `func (p *Poller) SetInterval(d time.Duration)`

Both `Run` loops currently create one `time.NewTicker` before the loop, so a new interval would never be observed. Both change to a timer reset each iteration from the current value.

- [ ] **Step 1: Write the failing tests**

Append to `internal/health/checker_test.go`:

```go
func TestCheckerReconfigure(t *testing.T) {
	c := NewChecker(&fakeLister{}, 30*time.Second, 5*time.Second, 8, slog.Default())
	c.Reconfigure(10*time.Second, 2*time.Second, 3)

	i, to, w := c.Config()
	if i != 10*time.Second || to != 2*time.Second || w != 3 {
		t.Errorf("got %v/%v/%d, want 10s/2s/3", i, to, w)
	}
}

// Zero workers would mean no probes ever run, so the floor NewChecker applies
// has to apply here too.
func TestCheckerReconfigureFloorsWorkers(t *testing.T) {
	c := NewChecker(&fakeLister{}, 30*time.Second, 5*time.Second, 8, slog.Default())
	c.Reconfigure(10*time.Second, 2*time.Second, 0)
	if _, _, w := c.Config(); w < 1 {
		t.Errorf("workers dropped to %d, which would stop every probe", w)
	}
}

// A shortened interval must be observed by a Run already in flight, not only
// after a restart.
func TestCheckerRunObservesNewInterval(t *testing.T) {
	lister := &countingLister{}
	c := NewChecker(lister, time.Hour, time.Second, 1, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	waitFor(t, func() bool { return lister.Calls() >= 1 }) // the immediate first cycle
	c.Reconfigure(5*time.Millisecond, time.Millisecond, 1)
	waitFor(t, func() bool { return lister.Calls() >= 3 })
}
```

`fakeLister` is the existing test double in that file. `countingLister` counts `Services()` calls under a mutex, and `waitFor` polls a condition for up to two seconds and calls `t.Fatal` on timeout — add both to the test file if they are not there:

```go
type countingLister struct {
	mu sync.Mutex
	n  int
}

func (c *countingLister) Services() ([]store.Service, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return nil, nil
}

func (c *countingLister) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within two seconds")
}
```

Append to `internal/discovery/poller_test.go`:

```go
func TestPollerSetInterval(t *testing.T) {
	src := &countingSource{}
	p := NewPoller(src, time.Hour, nil, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	waitForPolls(t, src, 1) // the immediate first cycle
	p.SetInterval(5 * time.Millisecond)
	waitForPolls(t, src, 3)
}
```

`countingSource` is a `dhcp.Source` counting `Leases` calls under a mutex, and `waitForPolls` is the same poll-until-true helper. Reuse the fake already in that file if one exists — check with `grep -n "dhcp.Source" internal/discovery/poller_test.go`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/health/ ./internal/discovery/ -run 'Reconfigure|SetInterval|NewInterval' -v`
Expected: FAIL — `Reconfigure`, `Config`, `SetInterval` undefined.

- [ ] **Step 3: Implement**

In `internal/health/checker.go`, guard the three tunables and read them per cycle:

```go
type Checker struct {
	lister Lister
	logger *slog.Logger
	now    func() time.Time

	cfgMu    sync.RWMutex
	interval time.Duration
	timeout  time.Duration
	workers  int

	mu      sync.RWMutex
	entries map[int64]*entry
}

// Reconfigure changes the probe schedule. A Run already in flight picks the
// new interval up on its next cycle rather than at the next restart.
func (c *Checker) Reconfigure(interval, timeout time.Duration, workers int) {
	if workers < 1 {
		workers = 8
	}
	c.cfgMu.Lock()
	defer c.cfgMu.Unlock()
	c.interval, c.timeout, c.workers = interval, timeout, workers
}

// Config returns the live schedule.
func (c *Checker) Config() (interval, timeout time.Duration, workers int) {
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()
	return c.interval, c.timeout, c.workers
}
```

`NewChecker` sets the fields through `Reconfigure` so the worker floor lives in one place. `Run` becomes a timer reset per cycle:

```go
func (c *Checker) Run(ctx context.Context) {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		c.CheckOnce(ctx)
		interval, _, _ := c.Config()
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(interval)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
```

The first `NewTimer(0)` fires immediately and is drained by the `Stop`/select above before the first `Reset`, preserving the existing behaviour of an immediate first cycle. `CheckOnce` reads its timeout and worker count from `c.Config()` rather than the fields directly.

`internal/discovery/poller.go` takes the same shape:

```go
// SetInterval changes the poll cadence. A Run already in flight picks it up on
// its next cycle.
func (p *Poller) SetInterval(d time.Duration) {
	p.cfgMu.Lock()
	defer p.cfgMu.Unlock()
	p.interval = d
}

func (p *Poller) Interval() time.Duration {
	p.cfgMu.RLock()
	defer p.cfgMu.RUnlock()
	return p.interval
}
```

with `Run` rewritten to the same timer-reset loop, reading `p.Interval()` each cycle.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/health/ ./internal/discovery/ -race -v`
Expected: PASS, including the pre-existing tests.

- [ ] **Step 5: Commit**

```bash
git add internal/health/ internal/discovery/
git commit -m "feat(health,discovery): observe a changed interval without a restart

Both Run loops reset a timer each cycle from the current interval instead
of holding a ticker built once at startup, so a schedule change takes
effect on the next cycle."
```

---

### Task 11: Wire the process to the database

**Files:**
- Modify: `internal/app/serve.go`
- Test: `internal/app/settings_test.go` (create)

**Interfaces:**
- Consumes: everything from Tasks 1 through 10.
- Produces:
  - `func ensureSettings(st *store.Store, cfg *config.Config, logger *slog.Logger) (store.Settings, error)` — seed on first run, return what the process boots with
  - `type RestartItem struct { Key, Running, Stored string }`
  - `func restartPending(boot store.Settings, cur store.Settings) []RestartItem`

- [ ] **Step 1: Write the failing test**

Create `internal/app/settings_test.go`:

```go
package app

import (
	"log/slog"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/config"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func TestEnsureSettingsSeedsOnce(t *testing.T) {
	st := testStore(t)
	cfg := testConfig(t, "data_dir: "+t.TempDir()+"\ndns:\n  private_domain: first.example\n")

	boot, err := ensureSettings(st, cfg, slog.Default())
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if boot.PrivateDomain != "first.example" {
		t.Fatalf("the file did not seed the database: %+v", boot)
	}

	// An operator edits the value in the UI.
	stored, _, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	stored.PrivateDomain = "edited.example"
	if err := st.PutSettings(stored); err != nil {
		t.Fatal(err)
	}

	// A second start with a different file must not overwrite it. This is the
	// whole precedence rule: the database wins, the file seeds once.
	cfg2 := testConfig(t, "data_dir: "+t.TempDir()+"\ndns:\n  private_domain: second.example\n")
	boot, err = ensureSettings(st, cfg2, slog.Default())
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if boot.PrivateDomain != "edited.example" {
		t.Errorf("the config file overwrote a stored setting: %q", boot.PrivateDomain)
	}
}

// A config file that would seed an invalid database must fail at startup
// rather than store something the UI can never save again.
func TestEnsureSettingsRejectsAnInvalidSeed(t *testing.T) {
	st := testStore(t)
	cfg := testConfig(t, "data_dir: "+t.TempDir()+"\ndns:\n  allow_query: [\"0.0.0.0/0\"]\n")
	if _, err := ensureSettings(st, cfg, slog.Default()); err == nil {
		t.Fatal("an open-resolver ACL was seeded from the file with no complaint")
	}
}

func TestRestartPending(t *testing.T) {
	boot := store.Settings{PrivateDomain: "home.arpa", DHCPLeaseFile: ""}

	if got := restartPending(boot, boot); len(got) != 0 {
		t.Errorf("unchanged settings report a pending restart: %+v", got)
	}

	cur := boot
	cur.PrivateDomain = "lab.example"
	cur.DHCPLeaseFile = "/var/lib/misc/dnsmasq.leases"
	got := restartPending(boot, cur)
	if len(got) != 2 {
		t.Fatalf("got %d pending items, want 2: %+v", len(got), got)
	}
	// The banner has to name both values, or the operator cannot tell which
	// one is actually serving queries right now.
	for _, it := range got {
		if it.Running == "" || it.Stored == "" || it.Key == "" {
			t.Errorf("incomplete item: %+v", it)
		}
	}

	// Only these two keys are restart-required. Everything else applies live,
	// so a live-applied change must never raise the banner.
	live := boot
	live.TTL = 999
	live.LogQueries = true
	if got := restartPending(boot, live); len(got) != 0 {
		t.Errorf("a live-applied change raised the restart banner: %+v", got)
	}
}
```

`testStore` and `testConfig` are helpers: open a store in `t.TempDir()`, and write a config file to `t.TempDir()` and `config.Load` it. Check `internal/app/serve_test.go` for existing ones with `grep -n "func test" internal/app/*_test.go` and reuse rather than duplicating.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/app/ -run 'EnsureSettings|RestartPending' -v`
Expected: FAIL — `ensureSettings`, `restartPending` undefined.

- [ ] **Step 3: Implement the seed and the restart check**

Add to `internal/app/serve.go`:

```go
// ensureSettings returns the settings the process will boot with. On a fresh
// database the config file seeds them; after that the database owns them and
// the file's moved keys are ignored.
func ensureSettings(st *store.Store, cfg *config.Config, logger *slog.Logger) (store.Settings, error) {
	cur, ok, err := st.Settings()
	if err != nil {
		return store.Settings{}, err
	}
	if ok {
		// Validate what we load: a database edited by hand, or written by an
		// older version, must not start a half-configured server.
		if err := settings.Validate(cur, publicConfirmation(cur)); err != nil {
			return store.Settings{}, fmt.Errorf("stored settings: %w", err)
		}
		return cur, nil
	}
	seed := cfg.SeedSettings()
	if err := settings.Validate(seed, publicConfirmation(seed)); err != nil {
		return store.Settings{}, fmt.Errorf("seed from config file: %w", err)
	}
	if err := st.PutSettings(seed); err != nil {
		return store.Settings{}, err
	}
	logger.Info("seeded settings from the config file",
		"path", "the config file", "note", "later edits to those keys are ignored; use the web UI")
	return seed, nil
}

// publicConfirmation re-confirms what is already stored. A prefix that got past
// the guardrail once must not block startup forever, and the warning below is
// what keeps it visible.
func publicConfirmation(v store.Settings) string {
	if pub := settings.PublicPrefixes(v.AllowQuery); len(pub) > 0 {
		return pub[0]
	}
	return ""
}
```

That helper only re-confirms the first public prefix, so a stored second one still fails startup. That is deliberate — reaching that state needs two separate confirmed saves, and refusing to start is the safer answer.

Also warn at every start while a public range is configured:

```go
	for _, p := range settings.PublicPrefixes(boot.AllowQuery) {
		logger.Warn("query ACL reaches beyond your LAN; KyDNS is an open resolver for this range",
			"prefix", p,
			"fix", "remove it under Settings, Server settings, allow_query")
	}
```

And the restart tracker:

```go
// RestartItem is one setting whose stored value differs from the one the
// process is running.
type RestartItem struct {
	Key     string
	Running string
	Stored  string
}

// restartPending compares the boot values of the two settings that cannot be
// applied live. There is no dirty flag to drift out of sync: the comparison
// becomes equal on the next restart and the banner clears itself.
func restartPending(boot, cur store.Settings) []RestartItem {
	var out []RestartItem
	add := func(key, running, stored string) {
		if running != stored {
			out = append(out, RestartItem{Key: key, Running: running, Stored: stored})
		}
	}
	add("dns.private_domain", boot.PrivateDomain, cur.PrivateDomain)
	add("discovery.dhcp_lease_file", orOff(boot.DHCPLeaseFile), orOff(cur.DHCPLeaseFile))
	return out
}

func orOff(s string) string {
	if s == "" {
		return "off"
	}
	return s
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/app/ -run 'EnsureSettings|RestartPending' -race -v`
Expected: PASS.

- [ ] **Step 5: Rewire Serve to read settings from the store**

In `Serve`, after the store is open, replace every read of `cfg.DNS.*`, `cfg.Discovery.*` and `cfg.Health.*` with the booted settings and the live snapshot. The changes, in order:

```go
	boot, err := ensureSettings(st, cfg, logger)
	if err != nil {
		return err
	}
	settingsHolder := settings.NewHolder(func() (store.Settings, error) {
		v, ok, err := st.Settings()
		if err != nil {
			return v, err
		}
		if !ok {
			return v, errors.New("settings row vanished")
		}
		return v, nil
	})
	if err := settingsHolder.Rebuild(); err != nil {
		return fmt.Errorf("initial settings: %w", err)
	}
	snap := settingsHolder.Current()
```

- The `reverse` slice built from `cfg.DNS.ReverseZones` is deleted. The zone holder's source closure reads `settingsHolder.Current().ReverseZones` instead, so a change to reverse zones is picked up by the next `holder.Rebuild()`.
- `registry.New(st, cfg.PrivateFQDN(), ...)` becomes `registry.New(st, dns.Fqdn(strings.ToLower(boot.PrivateDomain)), ...)`. `private_domain` is restart-required, so the boot value is the right one for the whole process lifetime.
- `dnsserver.NewACL(allowed)` becomes `dnsserver.NewACL(snap.AllowQuery)`.
- `dnsserver.NewCache(...)` takes the values from `boot`.
- `upstream.NewAll(...)` is deleted; `dnsserver.NewForwarder(snap.Upstreams, 2*time.Second, cache)`.
- The `Authoritative` literal becomes `dnsserver.NewAuthoritative(boot private FQDN, uint32(boot.TTL), snap.ReverseZones)`.
- `health.NewChecker` and the poller take their values from `boot`.
- `warnUnreachableViews(st, cfg, logger)` takes `boot.AllowTailscale` instead of the config.
- `web.Options.AllowTailscale` is deleted in favour of reading the live snapshot; see Task 13.

Then build the applier and the service:

```go
	apply := func(s *settings.Snapshot) {
		acl.Replace(s.AllowQuery)
		fwd.Replace(s.Upstreams)
		cache.Retune(s.Raw.CacheEntries, s.Raw.CacheMinTTL, s.Raw.CacheMaxTTL, s.Raw.NegativeMaxTTL)
		dnsSrv.SetLogging(s.Raw.LogQueries, s.Raw.LogClientIP)
		authoritative.SetTTL(uint32(s.Raw.TTL))
		authoritative.SetReverseZones(s.ReverseZones)
		checker.Reconfigure(
			time.Duration(s.Raw.HealthInterval)*time.Second,
			time.Duration(s.Raw.HealthTimeout)*time.Second,
			s.Raw.HealthWorkers)
		if poller != nil {
			poller.SetInterval(time.Duration(s.Raw.DiscoveryInterval) * time.Second)
		}
		// Reverse zones are an input to the snapshot, so it has to be rebuilt.
		if err := holder.Rebuild(); err != nil {
			logger.Error("snapshot rebuild after a settings change failed, still serving the previous snapshot", "error", err)
		}
		logger.Info("settings applied")
	}
	settingsSvc := settings.NewService(st, settingsHolder, apply)
```

`dnsSrv` is created after `apply` refers to it, so declare the variables before the closure exactly as the existing code already does for `poller`.

- [ ] **Step 6: Verify the whole process still starts and serves**

Run: `go test ./... -race`
Expected: PASS. The existing `internal/app` serve tests exercise startup end to end; fix anything the compiler or those tests catch.

Then run it by hand against a scratch directory to confirm a real start:

```bash
go build -o bin/kydns ./cmd/kydns
printf 'data_dir: %s\ndns:\n  listen: "127.0.0.1:15353"\nadmin:\n  listen: "127.0.0.1:18053"\n' /tmp/kydns-scratch > /tmp/kydns-scratch.yaml
./bin/kydns serve --config /tmp/kydns-scratch.yaml
```

Expected: it logs `seeded settings from the config file` on the first run and `kydns started`. Stop it, start it again, and confirm the seed line does not appear the second time.

- [ ] **Step 7: Commit**

```bash
git add internal/app/
git commit -m "feat(app): boot from the stored settings and apply changes live

The config file seeds the database on the first run; after that the
database owns those keys. apply constructs everything that can fail before
it swaps anything, so a rejected change leaves the running server alone.
private_domain and the lease file stay restart-required and say so."
```

---

### Task 12: The JSON API

**Files:**
- Create: `internal/adminapi/settings.go`
- Modify: `internal/adminapi/api.go` (the `API` struct, `Routes`, `snapshotDoc`, `importDoc`)
- Test: `internal/adminapi/settings_test.go`

**Interfaces:**
- Consumes: `settings.Service` from Task 5.
- Produces:
  - `func (a *API) WithSettings(s *settings.Service) *API`
  - `GET /api/v1/settings`, `PATCH /api/v1/settings`
  - `settings` as a field of the export document

- [ ] **Step 1: Write the failing test**

Create `internal/adminapi/settings_test.go`:

```go
package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetSettings(t *testing.T) {
	srv, _ := testAPIWithSettings(t)

	rec := srv.do(t, "GET", "/api/v1/settings", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["private_domain"] != "home.arpa" {
		t.Errorf("private_domain: %v", got["private_domain"])
	}
	if _, ok := got["upstreams"].([]any); !ok {
		t.Errorf("upstreams is not a list: %T", got["upstreams"])
	}
}

// PATCH merges: an absent key keeps its value, matching the blacklist settings
// endpoint and PATCH /services/{id}.
func TestPatchSettingsIsPartial(t *testing.T) {
	srv, svc := testAPIWithSettings(t)

	rec := srv.do(t, "PATCH", "/api/v1/settings", `{"ttl":120}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	cur, err := svc.Get()
	if err != nil {
		t.Fatal(err)
	}
	if cur.TTL != 120 {
		t.Errorf("ttl not applied: %d", cur.TTL)
	}
	if cur.PrivateDomain != "home.arpa" {
		t.Errorf("an absent key was clobbered: %q", cur.PrivateDomain)
	}
	if len(cur.Upstreams) == 0 {
		t.Error("an absent list was emptied")
	}
}

// An explicit empty list is a real instruction and must clear the value.
func TestPatchSettingsExplicitEmptyList(t *testing.T) {
	srv, svc := testAPIWithSettings(t)

	rec := srv.do(t, "PATCH", "/api/v1/settings", `{"reverse_zones":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	cur, _ := svc.Get()
	if len(cur.ReverseZones) != 0 {
		t.Errorf("an explicit empty list did not clear: %v", cur.ReverseZones)
	}
}

func TestPatchSettingsRejectsPublicACL(t *testing.T) {
	srv, svc := testAPIWithSettings(t)
	before, _ := svc.Get()

	rec := srv.do(t, "PATCH", "/api/v1/settings", `{"allow_query":["0.0.0.0/0"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "allow_query") {
		t.Errorf("the error does not name the field: %s", rec.Body)
	}
	after, _ := svc.Get()
	if len(after.AllowQuery) != len(before.AllowQuery) {
		t.Error("a rejected patch still changed the stored ACL")
	}
}

func TestPatchSettingsAcceptsConfirmedPublicACL(t *testing.T) {
	srv, svc := testAPIWithSettings(t)

	rec := srv.do(t, "PATCH", "/api/v1/settings",
		`{"allow_query":["192.168.0.0/16","0.0.0.0/0"],"confirm_public":"0.0.0.0/0"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	cur, _ := svc.Get()
	if len(cur.AllowQuery) != 2 {
		t.Errorf("the confirmed ACL was not stored: %v", cur.AllowQuery)
	}
}

// confirm_public is an instruction for this request, never a stored value.
func TestConfirmPublicIsNotPersisted(t *testing.T) {
	srv, _ := testAPIWithSettings(t)
	srv.do(t, "PATCH", "/api/v1/settings",
		`{"allow_query":["192.168.0.0/16","0.0.0.0/0"],"confirm_public":"0.0.0.0/0"}`)

	rec := srv.do(t, "GET", "/api/v1/settings", "")
	if strings.Contains(rec.Body.String(), "confirm_public") {
		t.Errorf("confirm_public was echoed back as stored state: %s", rec.Body)
	}
}

// A backup that omits settings is not a backup.
func TestExportIncludesSettings(t *testing.T) {
	srv, _ := testAPIWithSettings(t)
	rec := srv.do(t, "GET", "/api/v1/export?format=json", "")
	if !strings.Contains(rec.Body.String(), `"settings"`) {
		t.Errorf("export has no settings: %s", rec.Body)
	}
}

func TestImportRestoresSettings(t *testing.T) {
	srv, svc := testAPIWithSettings(t)
	rec := srv.do(t, "GET", "/api/v1/export?format=json", "")
	doc := rec.Body.String()

	srv.do(t, "PATCH", "/api/v1/settings", `{"ttl":999}`)
	if cur, _ := svc.Get(); cur.TTL != 999 {
		t.Fatal("setup failed")
	}

	if rec := srv.do(t, "POST", "/api/v1/import", doc); rec.Code >= 300 {
		t.Fatalf("import: %d %s", rec.Code, rec.Body)
	}
	cur, _ := svc.Get()
	if cur.TTL == 999 {
		t.Error("import did not restore the exported settings")
	}
}
```

`testAPIWithSettings` builds an `API` with a real store, a `settings.Service` over it, and a bearer token, returning a small helper whose `do` sends an authenticated request to `api.Handler()` and returns the `httptest.ResponseRecorder`. The existing `internal/adminapi/api_test.go` already builds an authenticated API for its own tests — read it first with `grep -n "func testAPI\|Authorization" internal/adminapi/api_test.go` and extend that helper rather than writing a parallel one.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/adminapi/ -run Settings -v`
Expected: FAIL — no route, `WithSettings` undefined.

- [ ] **Step 3: Implement**

Create `internal/adminapi/settings.go`:

```go
package adminapi

import (
	"net/http"

	"github.com/yoshiofthewire/kydns-server/internal/settings"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// settingsDTO is the wire form. It is a flat document because that is what a
// form posts and what a person editing JSON expects.
type settingsDTO struct {
	PrivateDomain     string   `json:"private_domain"`
	ReverseZones      []string `json:"reverse_zones"`
	Upstreams         []string `json:"upstreams"`
	AllowQuery        []string `json:"allow_query"`
	AllowTailscale    bool     `json:"allow_tailscale"`
	TTL               int      `json:"ttl"`
	CacheMinTTL       int      `json:"cache_min_ttl"`
	CacheMaxTTL       int      `json:"cache_max_ttl"`
	NegativeMaxTTL    int      `json:"negative_max_ttl"`
	CacheEntries      int      `json:"cache_entries"`
	LogQueries        bool     `json:"log_queries"`
	LogClientIP       bool     `json:"log_client_ip"`
	DHCPLeaseFile     string   `json:"dhcp_lease_file"`
	DiscoveryInterval int      `json:"discovery_interval"`
	HealthInterval    int      `json:"health_interval"`
	HealthTimeout     int      `json:"health_timeout"`
	HealthWorkers     int      `json:"health_workers"`

	// ConfirmPublic authorises one public allow_query prefix for this request
	// only. It is never stored and never returned.
	ConfirmPublic string `json:"confirm_public,omitempty"`
}

func toSettingsDTO(v store.Settings) settingsDTO {
	return settingsDTO{
		PrivateDomain: v.PrivateDomain, ReverseZones: v.ReverseZones,
		Upstreams: v.Upstreams, AllowQuery: v.AllowQuery,
		AllowTailscale: v.AllowTailscale, TTL: v.TTL,
		CacheMinTTL: v.CacheMinTTL, CacheMaxTTL: v.CacheMaxTTL,
		NegativeMaxTTL: v.NegativeMaxTTL, CacheEntries: v.CacheEntries,
		LogQueries: v.LogQueries, LogClientIP: v.LogClientIP,
		DHCPLeaseFile: v.DHCPLeaseFile, DiscoveryInterval: v.DiscoveryInterval,
		HealthInterval: v.HealthInterval, HealthTimeout: v.HealthTimeout,
		HealthWorkers: v.HealthWorkers,
	}
}

func fromSettingsDTO(d settingsDTO) store.Settings {
	return store.Settings{
		PrivateDomain: d.PrivateDomain, ReverseZones: d.ReverseZones,
		Upstreams: d.Upstreams, AllowQuery: d.AllowQuery,
		AllowTailscale: d.AllowTailscale, TTL: d.TTL,
		CacheMinTTL: d.CacheMinTTL, CacheMaxTTL: d.CacheMaxTTL,
		NegativeMaxTTL: d.NegativeMaxTTL, CacheEntries: d.CacheEntries,
		LogQueries: d.LogQueries, LogClientIP: d.LogClientIP,
		DHCPLeaseFile: d.DHCPLeaseFile, DiscoveryInterval: d.DiscoveryInterval,
		HealthInterval: d.HealthInterval, HealthTimeout: d.HealthTimeout,
		HealthWorkers: d.HealthWorkers,
	}
}

func (a *API) requireSettings(w http.ResponseWriter) bool {
	if a.settings == nil {
		writeErr(w, http.StatusServiceUnavailable, "unavailable", "", "settings are not wired")
		return false
	}
	return true
}

func (a *API) getSettings(w http.ResponseWriter, _ *http.Request) {
	if !a.requireSettings(w) {
		return
	}
	cur, err := a.settings.Get()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toSettingsDTO(cur))
}

// patchSettings merges onto the current settings: an absent field keeps its
// value, an explicit empty list clears one.
func (a *API) patchSettings(w http.ResponseWriter, r *http.Request) {
	if !a.requireSettings(w) {
		return
	}
	cur, err := a.settings.Get()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	d := toSettingsDTO(cur)
	if !decode(w, r, &d) {
		return
	}
	if err := a.settings.Set(fromSettingsDTO(d), d.ConfirmPublic); err != nil {
		writeSettingsErr(w, err)
		return
	}
	out, err := a.settings.Get()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toSettingsDTO(out))
}

// writeSettingsErr turns a FieldError into the same shape every other endpoint
// returns, so a client highlights the input without special-casing settings.
func writeSettingsErr(w http.ResponseWriter, err error) {
	var fe settings.FieldError
	if errors.As(err, &fe) {
		writeErr(w, http.StatusBadRequest, "invalid", fe.Field, fe.Msg)
		return
	}
	writeRegistryErr(w, err)
}
```

Add `"errors"` to the imports. In `internal/adminapi/api.go`:

- add a `settings *settings.Service` field to `API`
- add `func (a *API) WithSettings(s *settings.Service) *API { a.settings = s; return a }`, matching `WithPolicy`
- register the two routes inside `Routes`, both wrapped in `auth`:

```go
	mux.HandleFunc("GET /api/v1/settings", auth(a.getSettings))
	mux.HandleFunc("PATCH /api/v1/settings", auth(a.patchSettings))
```

- add `Settings *settingsDTO` with a `json:"settings,omitempty"` tag to the `transfer` struct, populate it in `snapshotDoc` when the service is wired, and in `importDoc` call `a.settings.Set(fromSettingsDTO(*doc.Settings), "")` when the field is present. An import that carries a public prefix fails validation, which is correct: restoring an exposure needs the same deliberate confirmation that creating it did. Say so in the error.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/adminapi/ -race -v`
Expected: PASS.

- [ ] **Step 5: Wire it in `Serve`**

In `internal/app/serve.go`, change the API construction to `.WithSettings(settingsSvc)`.

Run: `go test ./... -race`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/adminapi/ internal/app/serve.go
git commit -m "feat(adminapi): read and patch settings over the API

PATCH merges onto the current values, matching the blacklist settings
endpoint, so a one-key change is one request. confirm_public authorises a
public allow_query prefix for a single request and is never stored.
Settings join the export document, because a backup that omits them is
not a backup."
```

---

### Task 13: The settings form

**Files:**
- Create: `internal/web/serversettings.go`
- Modify: `internal/web/middleware.go`, `internal/web/settings.go`, `internal/web/templates/settings.html`, `internal/web/templates/dashboard.html`, `internal/web/dashboard.go`
- Test: `internal/web/serversettings_test.go`

**Interfaces:**
- Consumes: `settings.Service`, `app.RestartItem`.
- Produces: `POST /settings/server`, and `Settings`/`RestartPending` in `web.Options`

`RestartItem` lives in `internal/app`, which imports `internal/web`, so `web` cannot import it back. Declare the display type in `web` and have `app` convert:

```go
// in internal/web
type RestartItem struct{ Key, Running, Stored string }
```

with `Options.RestartPending func() []RestartItem`.

- [ ] **Step 1: Write the failing test**

Create `internal/web/serversettings_test.go`:

```go
package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestSettingsPageRendersTheForm(t *testing.T) {
	srv := testServerWithSettings(t)
	body := srv.get(t, "/settings")

	for _, want := range []string{
		`name="private_domain"`, `name="upstreams"`, `name="allow_query"`,
		`name="ttl"`, `name="cache_entries"`, `name="log_queries"`,
		`name="allow_tailscale"`, `name="health_workers"`,
		`action="/settings/server"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the form is missing %s", want)
		}
	}
	// The three keys the file still owns stay visible and read-only.
	if !strings.Contains(body, "admin.listen") || !strings.Contains(body, "data_dir") {
		t.Error("the file-owned keys are no longer shown")
	}
}

func TestPostServerSettingsSaves(t *testing.T) {
	srv := testServerWithSettings(t)

	form := url.Values{
		"private_domain": {"home.arpa"},
		"reverse_zones":  {"192.168.1.0/24"},
		"upstreams":      {"tls://1.1.1.1:853"},
		"allow_query":    {"192.168.0.0/16"},
		"ttl":            {"120"},
		"cache_min_ttl":  {"5"}, "cache_max_ttl": {"3600"},
		"negative_max_ttl": {"300"}, "cache_entries": {"10000"},
		"discovery_interval": {"30"}, "health_interval": {"30"},
		"health_timeout": {"5"}, "health_workers": {"8"},
		"log_queries": {"on"},
	}
	rec := srv.post(t, "/settings/server", form)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want a redirect: %s", rec.Code, rec.Body)
	}
	cur, _ := srv.settings.Get()
	if cur.TTL != 120 {
		t.Errorf("ttl not saved: %d", cur.TTL)
	}
	if !cur.LogQueries {
		t.Error("the checkbox did not save")
	}
	// An unchecked checkbox posts nothing at all, which must mean off, not
	// unchanged: otherwise a toggle can be turned on but never off.
	if cur.LogClientIP {
		t.Error("an unchecked box was read as unchanged instead of off")
	}
}

// A rejected save must re-render with the field named and the operator's input
// still in the boxes, not discard what they typed.
func TestPostServerSettingsShowsFieldError(t *testing.T) {
	srv := testServerWithSettings(t)
	before, _ := srv.settings.Get()

	form := validForm()
	form.Set("allow_query", "0.0.0.0/0")
	rec := srv.post(t, "/settings/server", form)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "allow_query") {
		t.Error("the error does not name the field")
	}
	if !strings.Contains(body, "0.0.0.0/0") {
		t.Error("the rejected input was discarded instead of shown back")
	}
	after, _ := srv.settings.Get()
	if len(after.AllowQuery) != len(before.AllowQuery) {
		t.Error("a rejected save still changed the stored ACL")
	}
}

func TestPostServerSettingsAcceptsConfirmedPublicRange(t *testing.T) {
	srv := testServerWithSettings(t)
	form := validForm()
	form.Set("allow_query", "192.168.0.0/16\n0.0.0.0/0")
	form.Set("confirm_public", "0.0.0.0/0")

	if rec := srv.post(t, "/settings/server", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	// Once exposed, the dashboard must say so on every page load.
	if body := srv.get(t, "/"); !strings.Contains(body, "open resolver") {
		t.Error("no standing warning after a public range was allowed")
	}
}

func TestPostServerSettingsRequiresCSRF(t *testing.T) {
	srv := testServerWithSettings(t)
	form := validForm()
	form.Del("csrf_token")
	if rec := srv.postRaw(t, "/settings/server", form); rec.Code == http.StatusSeeOther {
		t.Fatal("a save without a CSRF token succeeded")
	}
}

func TestRestartPendingBanner(t *testing.T) {
	srv := testServerWithSettings(t)
	srv.restart = []RestartItem{{
		Key: "dns.private_domain", Running: "home.arpa", Stored: "lab.example",
	}}
	body := srv.get(t, "/settings")
	for _, want := range []string{"restart", "home.arpa", "lab.example"} {
		if !strings.Contains(body, want) {
			t.Errorf("the banner does not mention %q", want)
		}
	}
}
```

`testServerWithSettings` builds a `web.Server` with a real store, a `settings.Service`, and a logged-in session; `get`, `post` and `postRaw` are helpers that issue a request with (and without) the session's CSRF token. `internal/web/auth_test.go` and `internal/web/settings_test.go` already build a logged-in server — read them with `grep -n "func test" internal/web/*_test.go` and extend, rather than adding a third harness. `validForm` returns the same `url.Values` as the save test, including a valid `csrf_token`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/web/ -run 'ServerSettings|SettingsPageRenders|RestartPending' -v`
Expected: FAIL — the route and the form do not exist.

- [ ] **Step 3: Implement the handler**

Create `internal/web/serversettings.go`:

```go
package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/settings"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// lines splits a textarea into entries. Blank lines and stray whitespace are
// what a person actually types, so they are not an error.
func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// intField reads one numeric input. A non-number is reported against its own
// field rather than silently becoming zero.
func intField(r *http.Request, name string) (int, error) {
	raw := strings.TrimSpace(r.PostFormValue(name))
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, settings.FieldError{Field: name, Msg: "must be a whole number"}
	}
	return n, nil
}

func (s *Server) postServerSettings(w http.ResponseWriter, r *http.Request) {
	if s.o.Settings == nil {
		http.Error(w, "settings are not wired", http.StatusInternalServerError)
		return
	}
	v := store.Settings{
		PrivateDomain: strings.TrimSpace(r.PostFormValue("private_domain")),
		ReverseZones:  lines(r.PostFormValue("reverse_zones")),
		Upstreams:     lines(r.PostFormValue("upstreams")),
		AllowQuery:    lines(r.PostFormValue("allow_query")),
		DHCPLeaseFile: strings.TrimSpace(r.PostFormValue("dhcp_lease_file")),
		// An unchecked box posts nothing, so presence is the value. Reading it
		// any other way makes a toggle that can be turned on and never off.
		AllowTailscale: r.PostFormValue("allow_tailscale") != "",
		LogQueries:     r.PostFormValue("log_queries") != "",
		LogClientIP:    r.PostFormValue("log_client_ip") != "",
	}
	for _, f := range []struct {
		name string
		dst  *int
	}{
		{"ttl", &v.TTL},
		{"cache_min_ttl", &v.CacheMinTTL},
		{"cache_max_ttl", &v.CacheMaxTTL},
		{"negative_max_ttl", &v.NegativeMaxTTL},
		{"cache_entries", &v.CacheEntries},
		{"discovery_interval", &v.DiscoveryInterval},
		{"health_interval", &v.HealthInterval},
		{"health_timeout", &v.HealthTimeout},
		{"health_workers", &v.HealthWorkers},
	} {
		n, err := intField(r, f.name)
		if err != nil {
			s.serverSettingsError(w, r, v, err)
			return
		}
		*f.dst = n
	}

	if err := s.o.Settings.Set(v, strings.TrimSpace(r.PostFormValue("confirm_public"))); err != nil {
		s.serverSettingsError(w, r, v, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// serverSettingsError re-renders with the rejected input still in the boxes.
// Discarding what the operator typed is the fastest way to lose a long
// upstream list to a typo in one field.
func (s *Server) serverSettingsError(w http.ResponseWriter, r *http.Request, attempted store.Settings, err error) {
	data := s.settingsData("", "")
	data["Server"] = attempted
	data["ServerError"] = err.Error()
	var fe settings.FieldError
	if errors.As(err, &fe) {
		data["ServerErrorField"] = fe.Field
	}
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, r, "settings.html", data)
}
```

Add `"errors"` to the imports.

- [ ] **Step 4: Wire the data and the route**

In `internal/web/middleware.go`, add to `Options`:

```go
	// Settings is nil when the settings service is not wired, which the screen
	// renders as the old read-only table rather than a broken form.
	Settings *settings.Service

	// RestartPending names the settings whose stored value differs from the one
	// the process is running. Empty is the normal case.
	RestartPending func() []RestartItem
```

and delete `AllowTailscale`, whose one consumer (`unreachableViews`) now reads `s.o.Settings.Get()`.

In `internal/web/settings.go`:

- `configRows` shrinks to the three file-owned keys:

```go
	return []configRow{
		{"data_dir", c.DataDir},
		{"dns.listen", c.DNS.Listen},
		{"admin.listen", c.Admin.Listen},
	}
```

- `restartNote` becomes accurate for exactly those keys:

```go
const restartNote = "These three come from the config file and are read at startup. " +
	"Everything else is edited above and stored in the database, where the config " +
	"file no longer has any effect."
```

- `settingsData` adds `"Server"` (the current `store.Settings`), `"Restart"` (the pending items), and `"PublicRanges"` (`settings.PublicPrefixes` of the live ACL) to the map, leaving them absent when `Settings` is nil.

Register the route where the other settings posts are registered:

```go
	mux.HandleFunc("POST /settings/server", s.requireSession(s.postServerSettings))
```

matching whatever wrapper the neighbouring `POST /settings/views/new` uses.

- [ ] **Step 5: Implement the template**

In `internal/web/templates/settings.html`, add a card above the Views card. Follow the existing `class="card"`, `class="stack"`, and `class="grid"` idioms rather than introducing new ones, and add no new CSS unless `css/styles.css` genuinely lacks a class for it:

```html
{{with .Restart}}
<div class="banner">
  <strong>Restart to apply.</strong>
  <p>These were saved but cannot change while KyDNS is running:</p>
  <ul>
    {{range .}}<li><code>{{.Key}}</code>: running <code>{{.Running}}</code>, saved <code>{{.Stored}}</code></li>{{end}}
  </ul>
</div>
{{end}}

{{with .PublicRanges}}
<div class="banner error">
  <strong>KyDNS is an open resolver for {{range .}}<code>{{.}}</code> {{end}}</strong>
  <p>Anyone who can reach this server on port 53 can use it. Remove the range
     from allow_query below unless you meant to do this.</p>
</div>
{{end}}

{{with .Server}}
<div class="card">
  <h3>Server settings</h3>
  {{with $.ServerError}}<p class="error">{{.}}</p>{{end}}
  <form class="stack" method="post" action="/settings/server">
    <input type="hidden" name="csrf_token" value="{{$.CSRF}}">

    <label for="private_domain">Private domain <span class="muted">(restart required)</span></label>
    <input id="private_domain" name="private_domain" type="text" value="{{.PrivateDomain}}">

    <label for="upstreams">Upstreams, one per line, tried in order</label>
    <textarea id="upstreams" name="upstreams" rows="4">{{range .Upstreams}}{{.}}
{{end}}</textarea>

    <label for="allow_query">Allow queries from, one CIDR per line</label>
    <textarea id="allow_query" name="allow_query" rows="6">{{range .AllowQuery}}{{.}}
{{end}}</textarea>

    <label for="confirm_public" class="muted">To allow a range beyond your LAN, retype it here</label>
    <input id="confirm_public" name="confirm_public" type="text" placeholder="0.0.0.0/0">

    <label><input type="checkbox" name="allow_tailscale" {{if .AllowTailscale}}checked{{end}}> Allow Tailscale addresses (100.64.0.0/10)</label>

    <label for="reverse_zones">Reverse zones, one CIDR per line</label>
    <textarea id="reverse_zones" name="reverse_zones" rows="3">{{range .ReverseZones}}{{.}}
{{end}}</textarea>

    <label for="ttl">TTL on authoritative answers (seconds)</label>
    <input id="ttl" name="ttl" type="number" min="1" value="{{.TTL}}">

    <label for="cache_min_ttl">Cache minimum TTL</label>
    <input id="cache_min_ttl" name="cache_min_ttl" type="number" min="1" value="{{.CacheMinTTL}}">
    <label for="cache_max_ttl">Cache maximum TTL</label>
    <input id="cache_max_ttl" name="cache_max_ttl" type="number" min="1" value="{{.CacheMaxTTL}}">
    <label for="negative_max_ttl">Negative answer maximum TTL</label>
    <input id="negative_max_ttl" name="negative_max_ttl" type="number" min="1" value="{{.NegativeMaxTTL}}">
    <label for="cache_entries">Cache entries</label>
    <input id="cache_entries" name="cache_entries" type="number" min="1" value="{{.CacheEntries}}">

    <label><input type="checkbox" name="log_queries" {{if .LogQueries}}checked{{end}}> Log queries</label>
    <label><input type="checkbox" name="log_client_ip" {{if .LogClientIP}}checked{{end}}> Also log who asked</label>

    <label for="dhcp_lease_file">DHCP lease file <span class="muted">(restart required, empty is off)</span></label>
    <input id="dhcp_lease_file" name="dhcp_lease_file" type="text" value="{{.DHCPLeaseFile}}">
    <label for="discovery_interval">Lease poll interval (seconds)</label>
    <input id="discovery_interval" name="discovery_interval" type="number" min="1" value="{{.DiscoveryInterval}}">

    <label for="health_interval">Health check interval (seconds)</label>
    <input id="health_interval" name="health_interval" type="number" min="1" value="{{.HealthInterval}}">
    <label for="health_timeout">Health check timeout (seconds)</label>
    <input id="health_timeout" name="health_timeout" type="number" min="1" value="{{.HealthTimeout}}">
    <label for="health_workers">Concurrent probes</label>
    <input id="health_workers" name="health_workers" type="number" min="1" value="{{.HealthWorkers}}">

    <button type="submit">Save settings</button>
  </form>
</div>
{{end}}
```

Add the same `{{with .PublicRanges}}` banner to `dashboard.html`, and populate `PublicRanges` in `dashboard.go`'s data map. Update the existing unreachable-view message on the Views card, which currently reads "Set `allow_tailscale: true` in the config file and restart KyDNS", to point at the checkbox above instead.

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/web/ -race -v`
Expected: PASS.

- [ ] **Step 7: Look at it**

```bash
go build -o bin/kydns ./cmd/kydns && ./bin/kydns serve --config /tmp/kydns-scratch.yaml
```

Open `http://127.0.0.1:18053/settings`. Confirm: the form renders in the existing dark theme with no new CSS, saving a TTL redirects and shows the new value, entering `0.0.0.0/0` without confirmation shows a field error with the typed value still present, and changing the private domain raises the restart banner naming both values.

- [ ] **Step 8: Commit**

```bash
git add internal/web/ css/
git commit -m "feat(web): edit server settings from the settings page

The read-only config table shrinks to the three keys the file still owns.
A rejected save re-renders with the operator's input intact, and a public
allow_query range needs the prefix retyped and then says so on every page."
```

---

### Task 14: The CLI

**Files:**
- Create: `internal/cli/settings.go`
- Modify: `internal/cli/cli.go`, `cmd/kydns/main.go`
- Test: `internal/cli/settings_test.go`

**Interfaces:**
- Consumes: the API from Task 12.
- Produces: `kydns settings get`, `kydns settings set key=value ...`

- [ ] **Step 1: Write the failing test**

Create `internal/cli/settings_test.go`:

```go
package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSettingsGetPrints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"private_domain":"home.arpa","ttl":60,"upstreams":["tls://1.1.1.1:853"]}`))
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	if code := settingsCmd(clientFor(srv), []string{"get"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{"private_domain", "home.arpa", "ttl", "60"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output is missing %q:\n%s", want, out.String())
		}
	}
}

func TestSettingsSetSendsOnePatch(t *testing.T) {
	var got map[string]any
	var patches int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PATCH" {
			patches++
			json.NewDecoder(r.Body).Decode(&got)
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	code := settingsCmd(clientFor(srv), []string{"set", "ttl=120", "log_queries=true"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	// One request, so a set cannot lose a concurrent edit from the UI.
	if patches != 1 {
		t.Errorf("sent %d PATCH requests, want 1", patches)
	}
	if got["ttl"] != float64(120) {
		t.Errorf("ttl: %v", got["ttl"])
	}
	if got["log_queries"] != true {
		t.Errorf("log_queries: %v (%T)", got["log_queries"], got["log_queries"])
	}
	// A key the operator did not name must not be in the body at all.
	if _, ok := got["private_domain"]; ok {
		t.Error("an unnamed key was sent, which would clobber a concurrent edit")
	}
}

func TestSettingsSetListValue(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	var out, errOut bytes.Buffer
	settingsCmd(clientFor(srv), []string{"set", "upstreams=tls://1.1.1.1:853,tls://9.9.9.9:853"}, &out, &errOut)

	list, ok := got["upstreams"].([]any)
	if !ok || len(list) != 2 {
		t.Fatalf("upstreams: %#v", got["upstreams"])
	}
	if list[0] != "tls://1.1.1.1:853" {
		t.Errorf("order lost: %v", list)
	}
}

func TestSettingsSetRejectsUnknownKey(t *testing.T) {
	var out, errOut bytes.Buffer
	code := settingsCmd(&Client{}, []string{"set", "nonsense=1"}, &out, &errOut)
	if code == 0 {
		t.Fatal("an unknown key was accepted")
	}
	if !strings.Contains(errOut.String(), "nonsense") {
		t.Errorf("the error does not name the key: %s", errOut.String())
	}
}
```

`clientFor` builds a `*Client` pointed at the test server — check `internal/cli/cli_test.go` and `blacklist_test.go` for an existing helper with `grep -n "httptest.NewServer" internal/cli/*_test.go` and reuse it.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/cli/ -run Settings -v`
Expected: FAIL — `settingsCmd` undefined.

- [ ] **Step 3: Implement**

Create `internal/cli/settings.go`:

```go
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

const settingsUsage = `usage:
  kydns settings get
  kydns settings set <key>=<value> [<key>=<value> ...] [--confirm-public <cidr>]

keys:
  private_domain, reverse_zones, upstreams, allow_query, allow_tailscale,
  ttl, cache_min_ttl, cache_max_ttl, negative_max_ttl, cache_entries,
  log_queries, log_client_ip, dhcp_lease_file, discovery_interval,
  health_interval, health_timeout, health_workers

lists take commas: upstreams=tls://1.1.1.1:853,tls://9.9.9.9:853`

// settingsKinds is how a key's value is encoded on the wire. The CLI has to
// know, because "120" as a JSON string is not the same request as 120.
var settingsKinds = map[string]string{
	"private_domain": "string", "dhcp_lease_file": "string",
	"reverse_zones": "list", "upstreams": "list", "allow_query": "list",
	"allow_tailscale": "bool", "log_queries": "bool", "log_client_ip": "bool",
	"ttl": "int", "cache_min_ttl": "int", "cache_max_ttl": "int",
	"negative_max_ttl": "int", "cache_entries": "int",
	"discovery_interval": "int", "health_interval": "int",
	"health_timeout": "int", "health_workers": "int",
}

func settingsCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, settingsUsage)
		return 2
	}
	switch args[0] {
	case "get":
		return settingsGet(c, stdout, stderr)
	case "set":
		return settingsSet(c, args[1:], stdout, stderr)
	}
	fmt.Fprintln(stderr, settingsUsage)
	return 2
}

func settingsGet(c *Client, stdout, stderr io.Writer) int {
	var got map[string]any
	if err := c.Do("GET", "/api/v1/settings", nil, &got); err != nil {
		return fail(stderr, err)
	}
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch v := got[k].(type) {
		case []any:
			parts := make([]string, len(v))
			for i, e := range v {
				parts[i] = fmt.Sprint(e)
			}
			fmt.Fprintf(stdout, "%-20s %s\n", k, strings.Join(parts, ", "))
		case float64:
			fmt.Fprintf(stdout, "%-20s %s\n", k, strconv.FormatFloat(v, 'f', -1, 64))
		default:
			fmt.Fprintf(stdout, "%-20s %v\n", k, v)
		}
	}
	return 0
}

// settingsSet sends exactly the keys the operator named, in one PATCH. Sending
// only what was asked for means a set cannot clobber a concurrent edit made in
// the web UI.
func settingsSet(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, settingsUsage)
		return 2
	}
	body := map[string]any{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--confirm-public" {
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "--confirm-public needs a CIDR")
				return 2
			}
			body["confirm_public"] = args[i+1]
			i++
			continue
		}
		k, raw, ok := strings.Cut(args[i], "=")
		if !ok {
			fmt.Fprintf(stderr, "%q is not key=value\n", args[i])
			return 2
		}
		kind, known := settingsKinds[k]
		if !known {
			fmt.Fprintf(stderr, "unknown setting %q\n%s\n", k, settingsUsage)
			return 2
		}
		switch kind {
		case "int":
			n, err := strconv.Atoi(raw)
			if err != nil {
				fmt.Fprintf(stderr, "%s must be a whole number, got %q\n", k, raw)
				return 2
			}
			body[k] = n
		case "bool":
			b, err := strconv.ParseBool(raw)
			if err != nil {
				fmt.Fprintf(stderr, "%s must be true or false, got %q\n", k, raw)
				return 2
			}
			body[k] = b
		case "list":
			var out []string
			for _, part := range strings.Split(raw, ",") {
				if part = strings.TrimSpace(part); part != "" {
					out = append(out, part)
				}
			}
			// An explicit empty value clears the list rather than sending null.
			if out == nil {
				out = []string{}
			}
			body[k] = out
		default:
			body[k] = raw
		}
	}
	var got json.RawMessage
	if err := c.Do("PATCH", "/api/v1/settings", body, &got); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintln(stdout, "settings updated")
	return 0
}
```

In `internal/cli/cli.go`, dispatch `"settings"` to `settingsCmd` alongside `blacklist`. In `cmd/kydns/main.go`, add `"settings"` to the case that routes API-backed verbs, and to the usage text.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/cli/ -race -v && go build ./...`
Expected: PASS.

- [ ] **Step 5: Try it against the running server**

```bash
./bin/kydns serve --config /tmp/kydns-scratch.yaml &
KYDNS_URL=http://127.0.0.1:18053 KYDNS_TOKEN=$(cat /tmp/kydns-scratch/bootstrap-token) ./bin/kydns settings get
KYDNS_URL=http://127.0.0.1:18053 KYDNS_TOKEN=$(cat /tmp/kydns-scratch/bootstrap-token) ./bin/kydns settings set ttl=120
```

Expected: `get` prints the settings, `set` prints `settings updated`, and a second `get` shows `ttl 120`. Stop the server with the job control of your shell — do not `pkill` a pattern, which in this repo has repeatedly killed the caller's own shell.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/ cmd/kydns/
git commit -m "feat(cli): kydns settings get and set

set sends only the keys named, in one PATCH, so it cannot clobber an edit
made in the web UI between a read and a write."
```

---

### Task 15: Documentation

**Files:**
- Modify: `kydns.example.yaml`, `kydns.docker.yaml`, `README.md`, `AGENTS.md`, `SECURITY.md`, `DESGINE.md`
- Test: `internal/config/example_test.go`

- [ ] **Step 1: Update the example test first**

The example file is asserted against the code's defaults. Rewrite the assertions for the reduced file before rewriting the file, so the test is what proves the documentation is honest. In `internal/config/example_test.go`, keep `TestDockerConfigLoads` and the "the example must load" test, and add:

```go
// Every key the example still documents as live must be one the file actually
// owns. A key left in the file that the database now owns is documentation
// that lies.
func TestExampleDocumentsOnlySeedAndBootstrapKeys(t *testing.T) {
	raw, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "seeds the database on the first run") {
		t.Error("the example does not say the moved keys are seed values only")
	}
	for _, key := range []string{"data_dir", "listen"} {
		if !strings.Contains(text, key) {
			t.Errorf("the example no longer documents %s, which the file still owns", key)
		}
	}
}
```

Run: `go test ./internal/config/ -v`
Expected: FAIL until the file is rewritten.

- [ ] **Step 2: Rewrite `kydns.example.yaml`**

Restructure it into two clearly separated halves. The header explains the precedence rule in the operator's terms:

```yaml
# KyDNS configuration.
#
# Two kinds of setting live here.
#
# The first three are owned by this file. KyDNS needs them before it has a
# database or a web UI, so they are read at every start and changing them
# means restarting.
#
# Everything below them seeds the database on the first run and is then
# ignored. Edit those under Settings in the web UI, with `kydns settings set`,
# or over the API. Changing them here after the first start does nothing.
```

Keep the existing per-key comments, which are good, and add a one-line marker to each moved key noting it is a first-run seed. Keep the `dns.listen` and `admin.listen` comments as they are.

- [ ] **Step 3: Update `kydns.docker.yaml`**

Its two settings are both file-owned, so the file itself does not change. Update its header comment: it currently says it differs from the example "in exactly two settings", which is still true but for a new reason. Say that both keys it sets are file-owned, and that everything else is edited in the web UI.

- [ ] **Step 4: Update the prose docs**

- `README.md`: the configuration section stops being a YAML reference and becomes "three keys in a file, everything else in the UI". Add an Unraid paragraph: the container template's volume and port mappings cover all three, so there is nothing to edit by hand. Document `kydns settings get`/`set` next to the other CLI verbs, and `GET`/`PATCH /api/v1/settings` next to the other endpoints.
- `SECURITY.md`: document the `allow_query` guardrail — what counts as private, that a public prefix needs the prefix retyped, and that a configured public range produces a standing banner and a warning at every start. Note that import cannot restore a public prefix without a fresh confirmation.
- `AGENTS.md`: add `internal/settings` to the package list — "the settings snapshot the runtime reads, and the single path by which it changes". Update the `internal/config` line, which currently says `kydns.example.yaml` is asserted against the defaults, to describe the reduced file. Add the new spec and this plan to the Child DOX Index.
- `DESGINE.md`: add the settings holder alongside the zone and policy holders, and record that settings live in the database with the file seeding once.

- [ ] **Step 5: Verify**

Run: `go test ./... -race && go vet ./...`
Expected: PASS.

Then read `kydns.example.yaml` end to end as if you had never seen KyDNS. If any key leaves you unsure whether editing it does anything, the comment is not finished.

- [ ] **Step 6: Commit**

```bash
git add kydns.example.yaml kydns.docker.yaml README.md AGENTS.md SECURITY.md DESGINE.md internal/config/
git commit -m "docs: the config file owns three keys, the database owns the rest

The example file is split into what it owns and what it seeds once, because
a key that looks editable but is ignored is worse than no documentation."
```

---

## Self-Review

Run against the spec after the plan is written, before execution starts.

**Spec coverage**

| Spec section | Task |
|---|---|
| Stays in the file (three keys) | 13 (`configRows`), 15 |
| Moves to the database | 1, 6 |
| Live vs restart-required split | 7-10 (live), 11 (`restartPending`) |
| Precedence: database wins, file seeds once | 6, 11 |
| Settings holder, rejected alternatives | 4, 5 |
| Data model, newline lists, `ponytail:` marker | 1 |
| One validation path | 2 |
| allow_query guardrail and standing banner | 3, 11 (start warning), 13 (banners) |
| Write path, all-or-nothing apply | 5, 11 |
| Restart-required banner, no dirty flag | 11, 13 |
| API, CLI, export/import | 12, 14 |
| Web UI | 13 |
| Testing | every task; race coverage in 5, 7, 8 |
| Documentation | 15 |

No spec requirement is unassigned.

**Known risks the executor should watch**

1. **Task 9 has the widest blast radius.** Converting `Authoritative`'s exported fields to unexported atomics breaks every struct literal that builds one. Let the compiler enumerate them rather than grepping.
2. **Task 11 rewrites `Serve`.** Do it as one commit and lean on the existing `internal/app` tests. If they were passing before and fail after, the wiring is wrong, not the tests.
3. **Task 3's `IsPrivatePrefix` uses containment, not overlap.** `0.0.0.0/0` overlaps every private range without being one. Getting this backwards silently disables the guardrail, so `TestPrivatePrefixesNeedNoConfirmation` and `TestValidateRejectsPublicPrefixWithoutConfirmation` must both pass.
4. **Helper names are guesses.** Every task that reuses a test helper says to grep for the real name first. Do that rather than adding a second harness beside an existing one.

---
