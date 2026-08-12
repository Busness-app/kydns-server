# KyDNS Service Proxy Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a service answer DNS with a reverse proxy's address while its health check and reverse records keep tracking the real host.

**Architecture:** Two fields on `store.Service` — `ProxyAddress` and `RouteViaProxy`. In `zone.buildIndex`, forward records use the proxy address when routed while reverse records always derive from the real addresses. That split is the feature, and it also fixes a standing bug where several services sharing one address silently overwrite each other's reverse record.

**Tech Stack:** Go 1.26.5, `modernc.org/sqlite` (pure Go, no cgo), `github.com/miekg/dns`, `html/template`. No new dependencies.

## Global Constraints

- **There is no migration mechanism yet.** `internal/store/store.go:91` runs one `CREATE TABLE IF NOT EXISTS` block on open, which does **not** add columns to an existing table. A live database already exists with real data. Task 1 builds a `PRAGMA user_version` stepped migration and every later schema change uses it.
- Reverse records must **always** derive from a service's real addresses, never from `ProxyAddress`. This is the property the feature exists for.
- Routing changes what an answer says, never whether one exists. A view where `pick()` returns no addresses still produces no records for that service.
- Aliases are **address records, not CNAMEs** (`internal/zone/snapshot.go:117-124`). They follow the routing decision along with the primary name.
- `CGO_ENABLED=0` must keep building. `go.mod` must not change.
- Every task leaves `go build ./...`, `go vet ./...`, `gofmt -l .`, `go test ./...` clean.
- House style: YAGNI, short meaningful comments, no comment block defending why code is not wrong.

## File Structure

| File | Change |
|---|---|
| `internal/store/store.go` | Migration mechanism; two columns; service CRUD reads/writes them |
| `internal/store/model.go:17` | `Service` gains `ProxyAddress`, `RouteViaProxy` |
| `internal/registry/registry.go:52` | `PutService` validates the pair |
| `internal/zone/snapshot.go:106-131` | Forward/reverse split; reverse-collision warning |
| `internal/adminapi/api.go:48` | `serviceDTO` gains both fields |
| `internal/cli/` | `--proxy`, `--via-proxy` on `service add` |
| `internal/web/services.go`, `templates/services.html` | Form fields, table badge, `check_insecure` checkbox |
| `README.md` | The pattern, and the alias correction |

---

## Task 1: Migration mechanism and the two columns

**Files:**
- Modify: `internal/store/store.go:23-95` — schema block and `Open`
- Modify: `internal/store/model.go:17-24` — the `Service` struct
- Test: `internal/store/store_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `store.Service` gains `ProxyAddress string` and `RouteViaProxy bool`
  - `services` table gains `proxy_address TEXT NOT NULL DEFAULT ''` and `route_via_proxy INTEGER NOT NULL DEFAULT 0`
  - `Store.PutService` / `Services()` / `Service(id)` round-trip both

- [ ] **Step 1: Write the failing test**

Append to `internal/store/store_test.go`:

```go
// A database created before proxy routing existed must gain the new columns
// on open, not fail. This is the first schema change since v1 shipped with
// live data in it.
func TestOpenMigratesAnOlderDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")

	// Build a v1-shaped services table by hand, with a row in it.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE services (
		id             INTEGER PRIMARY KEY,
		name           TEXT NOT NULL UNIQUE,
		check_url      TEXT NOT NULL DEFAULT '',
		check_insecure INTEGER NOT NULL DEFAULT 0,
		created_at     INTEGER NOT NULL DEFAULT (unixepoch())
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO services(name) VALUES('legacy')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open() on a pre-migration database: %v", err)
	}
	defer s.Close()

	svcs, err := s.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "legacy" {
		t.Fatalf("Services() = %v, want the pre-existing row preserved", svcs)
	}
	if svcs[0].ProxyAddress != "" || svcs[0].RouteViaProxy {
		t.Errorf("migrated row = %+v, want the new fields at their zero values", svcs[0])
	}
}

// Opening twice must not re-apply a migration.
func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "twice.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatalf("second Open(): %v", err)
	}
	defer s.Close()
}

func TestServiceRoundTripsProxyFields(t *testing.T) {
	s := openTestStore(t)
	id, err := s.PutService(Service{
		Name:          "kypost",
		Addresses:     []Address{{Address: "192.168.1.30"}},
		ProxyAddress:  "192.168.1.20",
		RouteViaProxy: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Service(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProxyAddress != "192.168.1.20" || !got.RouteViaProxy {
		t.Errorf("Service() = %+v, want the proxy fields preserved", got)
	}

	// Turning routing off keeps the address, which is the point of two fields.
	got.RouteViaProxy = false
	if _, err := s.PutService(got); err != nil {
		t.Fatal(err)
	}
	got, err = s.Service(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProxyAddress != "192.168.1.20" || got.RouteViaProxy {
		t.Errorf("Service() = %+v, want the address kept and routing off", got)
	}
}
```

`internal/store/store_test.go` has no exported-name helper for opening a temp
store — read the top of the file and reuse whatever it does (most tests call
`Open(filepath.Join(t.TempDir(), "x.db"))` directly). Replace `openTestStore(t)`
above with that. Add `"database/sql"` and `"path/filepath"` to the test imports
if absent.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/store/ -run 'TestOpenMigrates|TestOpenIsIdempotent|TestServiceRoundTripsProxy'`
Expected: FAIL — `ProxyAddress` and `RouteViaProxy` are undefined.

- [ ] **Step 3: Add the fields to the model**

In `internal/store/model.go`, extend `Service`:

```go
type Service struct {
	ID            int64
	Name          string
	Addresses     []Address
	Aliases       []string
	CheckURL      string
	CheckInsecure bool

	// ProxyAddress is where clients are sent when RouteViaProxy is on. The
	// two are separate so routing can be turned off for a moment without
	// discarding the address.
	ProxyAddress  string
	RouteViaProxy bool
}
```

- [ ] **Step 4: Add the columns to the schema and a migration**

In `internal/store/store.go`, add the two columns to the `services` block
inside the `schema` constant, so a fresh database gets them directly:

```sql
CREATE TABLE IF NOT EXISTS services (
  id              INTEGER PRIMARY KEY,
  name            TEXT NOT NULL UNIQUE,
  check_url       TEXT NOT NULL DEFAULT '',
  check_insecure  INTEGER NOT NULL DEFAULT 0,
  proxy_address   TEXT NOT NULL DEFAULT '',
  route_via_proxy INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);
```

Then add the migration mechanism below the `schema` constant. `CREATE TABLE IF
NOT EXISTS` silently does nothing to an existing table, so an older database
needs `ALTER TABLE`:

```go
// migrations run in order on a database whose user_version is below their
// index+1. A fresh database gets everything from schema above and then skips
// straight to the end, because applying an ALTER to a column that is already
// there would fail.
var migrations = []string{
	`ALTER TABLE services ADD COLUMN proxy_address TEXT NOT NULL DEFAULT '';
	 ALTER TABLE services ADD COLUMN route_via_proxy INTEGER NOT NULL DEFAULT 0;`,
}

func migrate(db *sql.DB, freshDB bool) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if freshDB {
		version = len(migrations)
	}
	for i := version; i < len(migrations); i++ {
		if _, err := db.Exec(migrations[i]); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
	}
	if version < len(migrations) || freshDB {
		if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations))); err != nil {
			return err
		}
	}
	return nil
}
```

In `Open`, determine freshness *before* running `schema`, then call `migrate`
after it:

```go
	// A database with no services table has never been written by KyDNS, so
	// the schema below creates everything and no migration should run.
	fresh := false
	var n int
	if err := db.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='services'`).Scan(&n); err != nil {
		db.Close()
		return nil, err
	}
	fresh = n == 0

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := migrate(db, fresh); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
```

Add `"database/sql"` to the file's imports if it is not already there.

- [ ] **Step 5: Read and write the new columns**

In `internal/store/store.go`, update the three service statements found at
lines 186, 198 and 237:

```go
	res, err := tx.Exec(
		`INSERT INTO services(name, check_url, check_insecure, proxy_address, route_via_proxy) VALUES(?, ?, ?, ?, ?)`,
		svc.Name, svc.CheckURL, svc.CheckInsecure, svc.ProxyAddress, svc.RouteViaProxy)
```

```go
	if _, err := tx.Exec(
		`UPDATE services SET name=?, check_url=?, check_insecure=?, proxy_address=?, route_via_proxy=? WHERE id=?`,
		svc.Name, svc.CheckURL, svc.CheckInsecure, svc.ProxyAddress, svc.RouteViaProxy, svc.ID)
```

```go
	err := s.db.QueryRow(
		`SELECT id, name, check_url, check_insecure, proxy_address, route_via_proxy FROM services WHERE id = ?`, id).
		Scan(&svc.ID, &svc.Name, &svc.CheckURL, &svc.CheckInsecure, &svc.ProxyAddress, &svc.RouteViaProxy)
```

`Services()` runs the same `SELECT` over all rows — find it and extend its
column list and `Scan` identically. Let the compiler and the failing tests
point at any statement you miss.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/store/ -v`
Expected: PASS, including the three new tests.

Run: `go build ./... && go test ./...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/store/
git commit -m "Add proxy fields to services, with a migration to reach them

CREATE TABLE IF NOT EXISTS does nothing to a table that already exists,
so the first schema change since v1 shipped needs a real migration. A
user_version counter carries the next one too."
```

---

## Task 2: Validation

**Files:**
- Modify: `internal/registry/registry.go:52-80` — `PutService`
- Test: `internal/registry/registry_test.go`

**Interfaces:**
- Consumes: `store.Service.ProxyAddress`, `store.Service.RouteViaProxy` from Task 1; `ValidateAddress` (`internal/registry/validate.go:84`); `invalid(field, code, format, args...)`.
- Produces: `PutService` rejects `route_via_proxy` with an empty proxy address (code `proxy_address_required`) and a malformed proxy address.

- [ ] **Step 1: Write the failing test**

Append to `internal/registry/registry_test.go`:

```go
func TestPutServiceValidatesProxy(t *testing.T) {
	r := newTestRegistry(t)

	// Routing on with nowhere to route is the one invalid combination the
	// two-field design makes possible.
	_, err := r.PutService(store.Service{
		Name:          "kypost",
		Addresses:     []store.Address{{Address: "192.168.1.30"}},
		RouteViaProxy: true,
	})
	if err == nil {
		t.Fatal("PutService() error = nil with routing on and no proxy address")
	}
	if !strings.Contains(err.Error(), "proxy") {
		t.Errorf("error = %v, want it to name the proxy address", err)
	}

	if _, err := r.PutService(store.Service{
		Name:          "nas",
		Addresses:     []store.Address{{Address: "192.168.1.30"}},
		ProxyAddress:  "not-an-ip",
		RouteViaProxy: true,
	}); err == nil {
		t.Error("PutService() error = nil with a malformed proxy address")
	}

	// An address kept while routing is off is deliberate, not an error.
	if _, err := r.PutService(store.Service{
		Name:         "git",
		Addresses:    []store.Address{{Address: "192.168.1.30"}},
		ProxyAddress: "192.168.1.20",
	}); err != nil {
		t.Errorf("PutService() with routing off rejected: %v", err)
	}
}
```

`internal/registry/registry_test.go` has no `newTestRegistry`; read the top of
the file and reuse however the existing tests construct a `*Registry`, then
replace the `newTestRegistry(t)` call above. Add `"strings"` to the imports if
absent.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/registry/ -run TestPutServiceValidatesProxy`
Expected: FAIL — all three cases are currently accepted.

- [ ] **Step 3: Write the implementation**

In `internal/registry/registry.go`, inside `PutService`, after the address loop
that ends around line 71:

```go
	svc.ProxyAddress = strings.TrimSpace(svc.ProxyAddress)
	if svc.ProxyAddress != "" {
		if err := ValidateAddress(svc.ProxyAddress); err != nil {
			return 0, invalid("proxy_address", "proxy_address_invalid", "%s", err)
		}
	}
	if svc.RouteViaProxy && svc.ProxyAddress == "" {
		return 0, invalid("proxy_address", "proxy_address_required",
			"routing through a proxy needs a proxy address")
	}
```

Check `invalid`'s signature in that package before writing the first call —
if it does not take a format string, pass the message directly.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/registry/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/registry/
git commit -m "Validate the proxy address pair

Routing on with no address is the one combination two fields make
possible and nothing downstream could act on."
```

---

## Task 3: Split forward from reverse in the zone build

This is the feature. Everything before it was plumbing.

**Files:**
- Modify: `internal/zone/snapshot.go:106-131` — the service loop in `buildIndex`
- Modify: `internal/zone/snapshot.go:91` — `buildIndex` signature, to take a logger
- Test: `internal/zone/snapshot_test.go`

**Interfaces:**
- Consumes: `store.Service.ProxyAddress`, `store.Service.RouteViaProxy` from Task 1.
- Produces: no new exported API. `buildIndex` gains a `*slog.Logger` parameter; `Input` is unchanged.

- [ ] **Step 1: Write the failing tests**

Append to `internal/zone/snapshot_test.go`:

```go
// The headline behaviour: clients are sent to the proxy, reverse lookups still
// name the real host.
func TestProxyRoutedServiceAnswersWithTheProxy(t *testing.T) {
	snap := buildTestSnapshot(t, Input{
		Zone:         "home.arpa.",
		ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Services: []store.Service{{
			ID: 1, Name: "kypost",
			Addresses:     []store.Address{{Address: "192.168.1.30"}},
			Aliases:       []string{"webmail"},
			ProxyAddress:  "192.168.1.20",
			RouteViaProxy: true,
		}},
	})
	idx := snap.Views[""]

	for _, name := range []string{"kypost.home.arpa.", "webmail.home.arpa."} {
		rrs := idx.Forward[name]
		if len(rrs) != 1 || rrs[0].Value != "192.168.1.20" {
			t.Errorf("%s = %v, want the proxy address", name, rrs)
		}
	}
	if got := idx.Reverse["30.1.168.192.in-addr.arpa."]; got != "kypost.home.arpa." {
		t.Errorf("reverse for the real address = %q, want kypost.home.arpa.", got)
	}
	if got := idx.Reverse["20.1.168.192.in-addr.arpa."]; got != "" {
		t.Errorf("reverse for the proxy address = %q, want none", got)
	}
}

func TestUnroutedServiceIgnoresTheProxyAddress(t *testing.T) {
	snap := buildTestSnapshot(t, Input{
		Zone: "home.arpa.",
		Services: []store.Service{{
			ID: 1, Name: "kypost",
			Addresses:    []store.Address{{Address: "192.168.1.30"}},
			ProxyAddress: "192.168.1.20", // stored, routing off
		}},
	})
	rrs := snap.Views[""].Forward["kypost.home.arpa."]
	if len(rrs) != 1 || rrs[0].Value != "192.168.1.30" {
		t.Errorf("= %v, want the real address while routing is off", rrs)
	}
}

// Routing decides what an answer says, never whether one exists.
func TestProxyDoesNotCreateAServiceInAViewItIsAbsentFrom(t *testing.T) {
	snap := buildTestSnapshot(t, Input{
		Zone:  "home.arpa.",
		Views: []store.View{{Name: "lan", Subnets: []string{"192.168.1.0/24"}}},
		Services: []store.Service{{
			ID: 1, Name: "kypost",
			Addresses:     []store.Address{{Address: "100.64.0.5", View: "tailnet"}},
			ProxyAddress:  "192.168.1.20",
			RouteViaProxy: true,
		}},
	})
	if rrs := snap.Views["lan"].Forward["kypost.home.arpa."]; len(rrs) != 0 {
		t.Errorf("lan view = %v, want nothing: the service has no lan address", rrs)
	}
}

// The bug this fixes: two services on one address silently lose a reverse
// record. Resolution stays last-writer-wins, but it must be visible.
func TestSharedAddressLogsAReverseConflict(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	if _, err := Build(Input{
		Zone:         "home.arpa.",
		ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Services: []store.Service{
			{ID: 1, Name: "a", Addresses: []store.Address{{Address: "192.168.1.30"}}},
			{ID: 2, Name: "b", Addresses: []store.Address{{Address: "192.168.1.30"}}},
		},
	}, logger); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"192.168.1.30", "a.home.arpa.", "b.home.arpa."} {
		if !strings.Contains(out, want) {
			t.Errorf("log %q does not mention %q", out, want)
		}
	}
}
```

`Build(in Input) (*Snapshot, error)` is the current signature
(`internal/zone/snapshot.go:50`); Task 3 adds a `*slog.Logger` parameter to it
and to `NewHolder(src Source)` (`internal/zone/holder.go:18`). Read
`snapshot_test.go` and reuse however it builds snapshots today, replacing
`buildTestSnapshot(t, ...)` above. Add `"bytes"`, `"log/slog"` and `"strings"` to the imports as needed.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/zone/`
Expected: FAIL — the proxy fields are ignored, and `Build` takes no logger.

- [ ] **Step 3: Thread a logger into the build**

`Build` and `buildIndex` gain a `*slog.Logger` parameter. Where `Build` is
called in `internal/app/serve.go`, pass the existing `logger`. A nil logger
must not panic — default it at the top of `Build`:

```go
	if logger == nil {
		logger = slog.Default()
	}
```

`zone.NewHolder` takes a source function that returns `Input`; the holder
calls `Build`. Give `NewHolder` the logger too and let it pass one through,
so `serve.go` supplies it once.

- [ ] **Step 4: Split forward from reverse**

Replace the service loop in `internal/zone/snapshot.go` (currently lines
106-131):

```go
	for _, svc := range in.Services {
		addrs := pick(view, func(a store.Address) string { return a.View }, svc.Addresses)
		if len(addrs) == 0 {
			continue
		}
		primary := qualify(svc.Name, zone)

		// Forward records answer with the proxy when routed; reverse records
		// always name the real host, so several services behind one proxy
		// keep their own PTRs.
		answer := addrs
		if svc.RouteViaProxy && svc.ProxyAddress != "" {
			answer = []store.Address{{Address: svc.ProxyAddress}}
		}

		names := append([]string{primary}, nil...)
		for _, alias := range svc.Aliases {
			names = append(names, qualify(alias, zone))
		}
		for _, n := range names {
			rrs := make([]RR, 0, len(answer))
			for _, a := range answer {
				rrs = append(rrs, RR{Name: n, Type: addrType(a.Address), Value: a.Address})
			}
			idx.Forward[n] = rrs
		}

		// Only the primary name gets a PTR; aliases do not.
		for _, a := range addrs {
			addr, err := netip.ParseAddr(a.Address)
			if err != nil || !inZones(addr, in.ReverseZones) {
				continue
			}
			key := arpaName(addr)
			if prior, ok := idx.Reverse[key]; ok && prior != primary {
				logger.Warn("two services share an address, so its reverse record is ambiguous",
					"address", a.Address, "previous", prior, "now", primary,
					"fix", "give them different addresses, or set a proxy address on one")
			}
			idx.Reverse[key] = primary
		}
	}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/zone/ -v`
Expected: PASS, including the four new tests.

Run: `go build ./... && go test ./... -race`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/zone/ internal/app/serve.go
git commit -m "Answer with the proxy, reverse-resolve the real host

Forward and reverse stop sharing a source. That routes clients through
the proxy and fixes a standing bug where several services on one address
each overwrote the last one's reverse record with no trace."
```

---

## Task 4: API, CLI, export and import

**Files:**
- Modify: `internal/adminapi/api.go:48-55` — `serviceDTO`
- Modify: `internal/adminapi/` — wherever `serviceDTO` converts to and from `store.Service`
- Modify: `internal/cli/` — `service add` flags
- Test: `internal/adminapi/api_test.go`, `internal/cli/cli_test.go`

**Interfaces:**
- Consumes: `store.Service.ProxyAddress`, `store.Service.RouteViaProxy`.
- Produces: JSON and YAML keys `proxy_address` and `route_via_proxy`; CLI flags `--proxy` and `--via-proxy`.

- [ ] **Step 1: Write the failing test**

Append to `internal/adminapi/api_test.go`:

```go
func TestServiceProxyFieldsRoundTripThroughTheAPI(t *testing.T) {
	h, tok := newTestAPI(t)

	do(t, h, "POST", "/api/v1/services", tok,
		`{"name":"kypost","addresses":[{"address":"192.168.1.30"}],
		  "proxy_address":"192.168.1.20","route_via_proxy":true}`)

	rec := do(t, h, "GET", "/api/v1/services", tok, "")
	var got struct {
		Services []struct {
			Name          string `json:"name"`
			ProxyAddress  string `json:"proxy_address"`
			RouteViaProxy bool   `json:"route_via_proxy"`
		} `json:"services"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Services) != 1 {
		t.Fatalf("services = %d, want 1", len(got.Services))
	}
	if got.Services[0].ProxyAddress != "192.168.1.20" || !got.Services[0].RouteViaProxy {
		t.Errorf("= %+v, want the proxy fields", got.Services[0])
	}

	// Export must carry them, or a backup silently loses the routing.
	rec = do(t, h, "GET", "/api/v1/export?format=yaml", tok, "")
	for _, want := range []string{"proxy_address", "route_via_proxy"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("export does not contain %q", want)
		}
	}
}
```

`do(t, h, method, path, token, body)` is real, at `internal/adminapi/api_test.go:31`.
There is no `newTestAPI` — read the top of the file and reuse however the
existing tests build the handler and token, then replace `newTestAPI(t)` above.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/adminapi/ -run TestServiceProxyFieldsRoundTrip`
Expected: FAIL — the fields are dropped.

- [ ] **Step 3: Extend the DTO**

In `internal/adminapi/api.go`:

```go
type serviceDTO struct {
	ID            int64        `json:"id,omitempty" yaml:"-"`
	Name          string       `json:"name" yaml:"name"`
	Addresses     []addressDTO `json:"addresses" yaml:"addresses"`
	Aliases       []string     `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	CheckURL      string       `json:"check_url,omitempty" yaml:"check_url,omitempty"`
	CheckInsecure bool         `json:"check_insecure,omitempty" yaml:"check_insecure,omitempty"`
	ProxyAddress  string       `json:"proxy_address,omitempty" yaml:"proxy_address,omitempty"`
	RouteViaProxy bool         `json:"route_via_proxy,omitempty" yaml:"route_via_proxy,omitempty"`
}
```

Then find every place that builds a `serviceDTO` from a `store.Service` or the
reverse — the list handler, the get handler, create, patch, export and import —
and carry both fields through each. Grep for `CheckInsecure` in that package;
every site that mentions it needs the two new fields beside it.

- [ ] **Step 4: Add the CLI flags**

In the CLI's `service add`, beside the existing `--check` flag:

```go
	proxy := fs.String("proxy", "", "send DNS for this service to this address instead")
	viaProxy := fs.Bool("via-proxy", false, "answer with --proxy rather than the service's own address")
```

and set `ProxyAddress` and `RouteViaProxy` on the service being posted. The
service name is a positional argument that `flag` stops at, so it is peeled off
before parsing — follow whatever the existing code does there and do not
restructure it.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/adminapi/ ./internal/cli/ -v`
Expected: PASS.

Run: `go build ./... && go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/adminapi/ internal/cli/
git commit -m "Carry the proxy fields through the API and CLI

Export included, or a backup restores a service that quietly stops
routing through the proxy."
```

---

## Task 5: The Services screen

**Files:**
- Modify: `internal/web/services.go` — form parsing
- Modify: `internal/web/templates/services.html` — form fields and the table
- Test: `internal/web/services_test.go`

**Interfaces:**
- Consumes: `store.Service.ProxyAddress`, `store.Service.RouteViaProxy`, `store.Service.CheckInsecure`.
- Produces: form fields `proxy_address`, `route_via_proxy`, `check_insecure`.

- [ ] **Step 1: Write the failing test**

Append to `internal/web/services_test.go`:

```go
func TestServiceFormAcceptsProxyFields(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)

	postForm(t, h, "/services/new", url.Values{
		"name":            {"kypost"},
		"address":         {"192.168.1.30"},
		"proxy_address":   {"192.168.1.20"},
		"route_via_proxy": {"on"},
		"check_insecure":  {"on"},
		"csrf_token":      {csrf},
	}, c)

	svcs, err := srv.o.Registry.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 {
		t.Fatalf("services = %d, want 1", len(svcs))
	}
	if svcs[0].ProxyAddress != "192.168.1.20" || !svcs[0].RouteViaProxy {
		t.Errorf("= %+v, want the proxy fields set", svcs[0])
	}
	if !svcs[0].CheckInsecure {
		t.Error("check_insecure was not applied; it had no control before this change")
	}

	// The indirection has to be visible on the list, not buried in an edit.
	body := page(t, h, "/services", c)
	if !strings.Contains(body, "192.168.1.20") {
		t.Error("services table does not show the proxy address on a routed row")
	}
}
```

These are the real helpers: `loggedIn(t) (http.Handler, *Server, *http.Cookie, string)`
at `internal/web/services_test.go:13` — the fourth return is the CSRF token —
`page` at `:35`, and `postForm(t, h, path, url.Values, cookie)` at
`internal/web/auth_test.go:59`. Every form post needs `csrf_token`; the
middleware rejects it otherwise.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/web/ -run TestServiceFormAcceptsProxyFields`
Expected: FAIL — the handler ignores all three fields.

- [ ] **Step 3: Parse the fields**

In `internal/web/services.go`, in `postServiceNew` (line 80) beside the
existing `check_url` read:

```go
	svc.ProxyAddress = strings.TrimSpace(r.PostFormValue("proxy_address"))
	svc.RouteViaProxy = r.PostFormValue("route_via_proxy") != ""
	svc.CheckInsecure = r.PostFormValue("check_insecure") != ""
```

- [ ] **Step 4: Add the form controls and the table column**

In `internal/web/templates/services.html`, after the health check URL field:

```html
    <label for="proxy_address">Proxy address (optional)</label>
    <input id="proxy_address" name="proxy_address" type="text" placeholder="192.168.1.20">
    <label><input name="route_via_proxy" type="checkbox"> Send DNS to the proxy</label>
    <p class="muted">Clients resolve to the proxy while the health check below
       still targets the service itself. Check the service directly, not the
       proxy — a proxy returning 502 for a dead backend still looks healthy.</p>
    <label><input name="check_insecure" type="checkbox"> Accept a self-signed certificate on the check</label>
```

In the services table, show the routing on each row:

```html
      <td>{{range .Addresses}}{{.Address}}{{if .View}} <span class="badge">{{.View}}</span>{{end}} {{end}}
          {{if .RouteViaProxy}}<span class="badge warn">&rarr; {{.ProxyAddress}}</span>{{end}}</td>
```

Match the surrounding table's existing column structure — read the file before
editing so the cell lands in the addresses column rather than a new one.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/web/ -v`
Expected: PASS.

- [ ] **Step 6: Drive the real binary**

Every plan in this project has found a bug here that the tests missed.

```bash
go build -o /tmp/kydns ./cmd/kydns
mkdir -p /tmp/kydns-data
cat > /tmp/kydns-test.yaml <<'YAML'
data_dir: /tmp/kydns-data
dns:
  listen: "127.0.0.1:15353"
  allow_query: ["127.0.0.0/8"]
  reverse_zones: ["192.168.1.0/24"]
admin:
  listen: "127.0.0.1:18053"
YAML
/tmp/kydns serve --config /tmp/kydns-test.yaml
```

Complete setup in the browser, add a service at `192.168.1.30` with proxy
`192.168.1.20` and routing on, then check both directions:

```bash
dig @127.0.0.1 -p 15353 kypost.home.arpa A +short          # want 192.168.1.20
dig @127.0.0.1 -p 15353 -x 192.168.1.30 +short             # want kypost.home.arpa.
dig @127.0.0.1 -p 15353 -x 192.168.1.20 +short             # want nothing
```

Then add a second service on `192.168.1.30` and confirm the conflict warning
appears in the server log. Clean up: `rm -rf /tmp/kydns-data /tmp/kydns-test.yaml /tmp/kydns`

- [ ] **Step 7: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/web/
git commit -m "Add proxy routing and the missing insecure-check box to the form

check_insecure has been in the model and the API since v1 with no
control in the UI, so a self-signed service sat permanently down with no
way to fix it from a browser."
```

---

## Task 6: Documentation

**Files:**
- Modify: `README.md` — the services section

**Interfaces:**
- Consumes: everything above.
- Produces: nothing code depends on.

- [ ] **Step 1: Correct the alias claim and document the pattern**

The README implies aliases are CNAMEs. They are address records
(`internal/zone/snapshot.go:117-124` copies the address records to each alias
name). Fix any wording that says otherwise, then add:

````markdown
### Putting a service behind a reverse proxy

A service speaking plain HTTP behind a proxy that terminates TLS wants two
different addresses: clients should reach the proxy, monitoring should reach
the service.

Register the service at its **real** address, set the proxy address, and tick
"Send DNS to the proxy":

```sh
kydns service add kypost \
  --address 192.168.1.30 \
  --proxy 192.168.1.20 --via-proxy \
  --check http://192.168.1.30:8080/health
```

`kypost.urlxl.us` now answers `192.168.1.20`, and so does every alias. The
reverse record for `192.168.1.30` still names `kypost.urlxl.us`, so several
services behind one proxy each keep a correct PTR.

Point the health check at the service, not the proxy. A proxy returning 502 for
a dead backend still answers a prober perfectly, so checking the proxy tells you
only that the proxy is up.

Untick the box to send clients straight at the service without losing the proxy
address — the fastest way to tell whether a problem is the application or the
proxy in front of it.
````

- [ ] **Step 2: Verify nothing else drifted**

Run: `go test ./internal/config/ -run TestExample`
Expected: PASS — no config settings changed, but the guard confirms it.

Read the README's services section against `internal/web/templates/services.html`
and confirm every field named in prose exists on the form.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "Document proxy routing, and stop calling aliases CNAMEs

Aliases are address records copied from the service, which matters now
that routing changes what gets copied."
```

---

## Self-review

Checked against `docs/superpowers/specs/2026-08-12-kydns-service-proxy-routing.md`:

| Spec section | Task |
|---|---|
| Part 1 — model fields, validation of the pair | 1, 2 |
| Part 1 — schema columns with defaults | 1 |
| Part 2 — forward uses proxy, reverse uses real | 3 |
| Part 2 — view selection first, absent view stays absent | 3 |
| Part 2 — aliases follow routing | 3 |
| Part 3 — reverse-collision warning | 3 |
| Part 4 — Services form, table badge | 5 |
| Part 4 — health check help text | 5 |
| Part 4 — `check_insecure` checkbox | 5 |
| Part 4 — API, CLI, export/import | 4 |
| Part 5 — every listed test | 1–5 |
| Part 6 — README, alias correction | 6 |

**Gap found and closed:** the spec assumed columns could simply be added.
`CREATE TABLE IF NOT EXISTS` does nothing to an existing table, and a live
database already holds data, so Task 1 builds a `user_version` migration first.
That is a genuine addition to the spec's scope, not a restatement of it.

**Type consistency:** `ProxyAddress`/`RouteViaProxy` are named identically in
Tasks 1–5; the JSON and YAML keys `proxy_address`/`route_via_proxy` match the
form field names, which keeps the API, the export and the web form aligned.
`buildIndex` and `Build` gain the same `*slog.Logger` in Task 3 and no later
task changes that signature.
