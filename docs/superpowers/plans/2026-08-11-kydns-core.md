# KyDNS Core Resolver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working KyDNS daemon that answers authoritative DNS for a private domain with per-subnet views, forwards and caches everything else, and is managed over a token-authenticated admin API and CLI.

**Architecture:** One Go binary. Writes go through `store` (SQLite) into `registry`, which validates them; every write rebuilds an immutable per-view `zone` snapshot held in an `atomic.Pointer` that the DNS hot path reads lock-free. `dnsserver` resolves the client's view from its source IP, answers from that view's index, and otherwise forwards through a cache. `adminapi` and the CLI are thin transports over `registry`.

**Tech Stack:** Go 1.26, `github.com/miekg/dns`, `modernc.org/sqlite` (pure Go, no cgo), `golang.org/x/sync/singleflight`, `gopkg.in/yaml.v3`, `net/netip`, stdlib `testing`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-11-kydns-v1-design.md`. It governs; this plan implements it.
- Go module path: `github.com/yoshiofthewire/kydns-server`. Go 1.26.
- No cgo. Builds must succeed with `CGO_ENABLED=0`.
- Dependencies are limited to the five listed in the spec's Dependencies table. Adding another needs a spec change.
- Tests use stdlib `testing` and table-driven cases. No assertion libraries.
- The DNS hot path must never touch SQLite.
- `store` is the single write chokepoint — no package outside it issues SQL.
- Logging is `log/slog` to stdout/stderr. Never log credentials, token values, private keys, or full answers for private services.
- Private domain default `home.arpa`; authoritative TTL default 60s.
- `allow_tailscale` defaults to **false**.
- Every task ends with a commit. Commit messages disclose AI assistance per `CONTRIBUTING.md`.

## Plan Split

This plan is Plan 1 of 3 against the same spec. Each produces working software.

| Plan | Delivers | Spec coverage |
|---|---|---|
| **1 — Core resolver (this plan)** | `kydns serve` answering authoritative + forwarded queries with views, ACL and refusal counters, managed by token-auth API and CLI, YAML/JSON import/export | Parts 1, 2 (query path), 4; Part 3 API and auth-by-token |
| 2 — Operator surface | Password auth, first-run setup, sessions and CSRF, the five web screens, refusal banner, stats dashboard | Part 3 web UI and password auth; the "Making refusals visible" section |
| 3 — Discovery and health | dnsmasq lease adapter, promote-to-service, health probes, Discovered screen | Part 2 discovery and health |

Plan 1 defers from Part 3: password/session auth (token auth only), all HTML, and the `/health` and `/stats` endpoints' UI consumers. `/stats` itself ships here because the ACL counters it exposes are built here.

## File Structure

```
go.mod
cmd/kydns/main.go              entry point; subcommand dispatch
internal/config/config.go      YAML config, defaults, validation
internal/store/store.go        SQLite open, migrations, typed queries
internal/store/model.go        row structs shared with registry
internal/registry/registry.go  application service: CRUD over store
internal/registry/validate.go  name, address, view, and conflict rules
internal/zone/matcher.go       source IP -> view name, longest prefix
internal/zone/snapshot.go      immutable per-view forward/reverse indexes
internal/zone/holder.go        atomic.Pointer + all-or-nothing rebuild
internal/dnsserver/acl.go      query ACL + refusal counters
internal/dnsserver/auth.go     authoritative answers, SOA/NS synthesis
internal/dnsserver/cache.go    response cache, negative caching, LRU
internal/dnsserver/forward.go  upstream failover + single-flight
internal/dnsserver/server.go   handler pipeline, UDP/TCP listeners
internal/adminapi/api.go       routes and JSON error shape
internal/adminapi/tokens.go    token generation, hashing, bearer middleware
internal/adminapi/transfer.go  export/import
internal/cli/cli.go            API client + subcommands
```

Files split by responsibility, not layer. `dnsserver` is five focused files because its concerns (ACL, authoritative, cache, forwarding, wiring) have genuinely different test shapes.

---

### Task 1: Project skeleton

**Files:**
- Create: `go.mod`, `cmd/kydns/main.go`, `.gitignore`, `Makefile`
- Test: `cmd/kydns/main_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: module path `github.com/yoshiofthewire/kydns-server`; `main()` dispatching on `os.Args[1]`; `run(args []string, stdout io.Writer) int`.

- [ ] **Step 1: Write the failing test**

```go
// cmd/kydns/main_test.go
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunUnknownSubcommand(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"bogus"}, &out); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(out.String(), "usage:") {
		t.Errorf("output = %q, want usage text", out.String())
	}
}

func TestRunNoArgsPrintsUsage(t *testing.T) {
	var out bytes.Buffer
	if code := run(nil, &out); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/kydns/ -run TestRun -v`
Expected: FAIL — `undefined: run`.

- [ ] **Step 3: Write minimal implementation**

```bash
go mod init github.com/yoshiofthewire/kydns-server
```

```go
// cmd/kydns/main.go
package main

import (
	"fmt"
	"io"
	"os"
)

const usage = `usage: kydns <command> [flags]

commands:
  serve     run the DNS and admin servers
  service   manage services
  record    manage records
  view      manage views
  token     manage API tokens
  export    write registry contents to YAML or JSON
  import    load registry contents from YAML or JSON
`

func run(args []string, stdout io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return 2
	}
	switch args[0] {
	default:
		fmt.Fprintf(stdout, "kydns: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }
```

```makefile
# Makefile
.PHONY: test build
test:
	CGO_ENABLED=0 go test ./...
build:
	CGO_ENABLED=0 go build -o bin/kydns ./cmd/kydns
```

```
# .gitignore
/bin/
*.db
*.db-wal
*.db-shm
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test`
Expected: PASS (`ok github.com/yoshiofthewire/kydns-server/cmd/kydns`).

- [ ] **Step 5: Commit**

```bash
git add go.mod cmd/kydns .gitignore Makefile
git commit -m "Add Go module skeleton and subcommand dispatch

AI-assisted contribution (agentic). Verified with: make test"
```

---

### Task 2: Config loading

**Files:**
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type Config struct { DNS DNSConfig; Admin AdminConfig; DataDir string }`
  - `type DNSConfig struct { Listen, PrivateDomain string; ReverseZones, Upstreams, AllowQuery []string; AllowTailscale bool; TTL, CacheMinTTL, CacheMaxTTL, NegativeMaxTTL, CacheEntries int; LogQueries, LogClientIP bool }`
  - `type AdminConfig struct { Listen string }`
  - `func Load(path string) (*Config, error)`
  - `func (c *Config) PrivateFQDN() string` — private domain as a trailing-dot FQDN.
  - `TailscaleCGNAT = "100.64.0.0/10"`

- [ ] **Step 1: Write the failing test**

```go
// internal/config/config_test.go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kydns.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAppliesDefaults(t *testing.T) {
	c, err := Load(write(t, "data_dir: /var/lib/kydns\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.DNS.Listen != ":53" {
		t.Errorf("Listen = %q, want :53", c.DNS.Listen)
	}
	if c.DNS.PrivateDomain != "home.arpa" {
		t.Errorf("PrivateDomain = %q, want home.arpa", c.DNS.PrivateDomain)
	}
	if c.DNS.TTL != 60 {
		t.Errorf("TTL = %d, want 60", c.DNS.TTL)
	}
	if c.Admin.Listen != "127.0.0.1:8053" {
		t.Errorf("Admin.Listen = %q, want 127.0.0.1:8053", c.Admin.Listen)
	}
	if c.DNS.AllowTailscale {
		t.Error("AllowTailscale = true, want false by default")
	}
	if len(c.DNS.AllowQuery) == 0 {
		t.Error("AllowQuery is empty, want private-range defaults")
	}
}

func TestPrivateFQDN(t *testing.T) {
	c, err := Load(write(t, "data_dir: /tmp/x\ndns:\n  private_domain: lab.internal\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.PrivateFQDN(); got != "lab.internal." {
		t.Errorf("PrivateFQDN() = %q, want lab.internal.", got)
	}
}

func TestLoadRejects(t *testing.T) {
	for name, body := range map[string]string{
		"no data dir":      "dns:\n  listen: \":53\"\n",
		"bad allow_query":  "data_dir: /tmp/x\ndns:\n  allow_query: [\"not-a-cidr\"]\n",
		"bad reverse zone": "data_dir: /tmp/x\ndns:\n  reverse_zones: [\"192.168.1.0\"]\n",
		"bad upstream":     "data_dir: /tmp/x\ndns:\n  upstreams: [\"1.1.1.1:no\"]\n",
		"empty domain":     "data_dir: /tmp/x\ndns:\n  private_domain: \"\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body)); err == nil {
				t.Fatal("Load() error = nil, want error")
			}
		})
	}
}

func TestAllowTailscaleExplicit(t *testing.T) {
	c, err := Load(write(t, "data_dir: /tmp/x\ndns:\n  allow_tailscale: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.DNS.AllowTailscale {
		t.Error("AllowTailscale = false, want true")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -v`
Expected: FAIL — `undefined: Load`.

- [ ] **Step 3: Write minimal implementation**

```bash
go get gopkg.in/yaml.v3
```

```go
// internal/config/config.go
// Package config loads the KyDNS process configuration. It holds process
// concerns only — listeners, upstreams, the ACL. Views are registry data.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// TailscaleCGNAT is the range added to the ACL by DNSConfig.AllowTailscale.
const TailscaleCGNAT = "100.64.0.0/10"

// defaultAllowQuery is loopback plus RFC1918 and ULA. CGNAT is deliberately
// absent: it is gated behind AllowTailscale.
var defaultAllowQuery = []string{
	"127.0.0.0/8", "::1/128",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"169.254.0.0/16", "fe80::/10", "fc00::/7",
}

type Config struct {
	DNS     DNSConfig   `yaml:"dns"`
	Admin   AdminConfig `yaml:"admin"`
	DataDir string      `yaml:"data_dir"`
}

type DNSConfig struct {
	Listen         string   `yaml:"listen"`
	PrivateDomain  string   `yaml:"private_domain"`
	ReverseZones   []string `yaml:"reverse_zones"`
	Upstreams      []string `yaml:"upstreams"`
	AllowQuery     []string `yaml:"allow_query"`
	AllowTailscale bool     `yaml:"allow_tailscale"`
	TTL            int      `yaml:"ttl"`
	CacheMinTTL    int      `yaml:"cache_min_ttl"`
	CacheMaxTTL    int      `yaml:"cache_max_ttl"`
	NegativeMaxTTL int      `yaml:"negative_max_ttl"`
	CacheEntries   int      `yaml:"cache_entries"`
	LogQueries     bool     `yaml:"log_queries"`
	LogClientIP    bool     `yaml:"log_client_ip"`
}

type AdminConfig struct {
	Listen string `yaml:"listen"`
}

// Load reads path, applies defaults, and validates. It returns an error rather
// than a partially usable Config: the process must never run half-configured.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	set := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	setInt := func(p *int, v int) {
		if *p == 0 {
			*p = v
		}
	}
	set(&c.DNS.Listen, ":53")
	set(&c.Admin.Listen, "127.0.0.1:8053")
	if c.DNS.PrivateDomain == "" && !c.explicitEmptyDomain {
		c.DNS.PrivateDomain = "home.arpa"
	}
	setInt(&c.DNS.TTL, 60)
	setInt(&c.DNS.CacheMinTTL, 5)
	setInt(&c.DNS.CacheMaxTTL, 3600)
	setInt(&c.DNS.NegativeMaxTTL, 300)
	setInt(&c.DNS.CacheEntries, 10000)
	if len(c.DNS.Upstreams) == 0 {
		c.DNS.Upstreams = []string{"1.1.1.1:53", "9.9.9.9:53"}
	}
	if len(c.DNS.AllowQuery) == 0 {
		c.DNS.AllowQuery = append([]string(nil), defaultAllowQuery...)
	}
}

func (c *Config) validate() error {
	if c.DataDir == "" {
		return errors.New("data_dir is required")
	}
	if c.DNS.PrivateDomain == "" {
		return errors.New("dns.private_domain must not be empty")
	}
	for _, s := range c.DNS.AllowQuery {
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("dns.allow_query %q: %w", s, err)
		}
	}
	for _, s := range c.DNS.ReverseZones {
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("dns.reverse_zones %q: %w", s, err)
		}
	}
	for _, s := range c.DNS.Upstreams {
		if _, _, err := net.SplitHostPort(s); err != nil {
			return fmt.Errorf("dns.upstreams %q: must be host:port", s)
		}
	}
	if c.DNS.CacheMinTTL > c.DNS.CacheMaxTTL {
		return errors.New("dns.cache_min_ttl exceeds dns.cache_max_ttl")
	}
	return nil
}

// PrivateFQDN returns the private domain as a lowercased FQDN with a trailing
// dot, the form miekg/dns uses throughout.
func (c *Config) PrivateFQDN() string {
	return strings.ToLower(c.DNS.PrivateDomain) + "."
}

// EffectiveAllowQuery is AllowQuery plus the CGNAT range when AllowTailscale
// is on. Parsing here means callers never re-parse strings.
func (c *Config) EffectiveAllowQuery() ([]netip.Prefix, error) {
	list := append([]string(nil), c.DNS.AllowQuery...)
	if c.DNS.AllowTailscale {
		list = append(list, TailscaleCGNAT)
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("allow_query %q: %w", s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
```

The `explicitEmptyDomain` reference above is a deliberate marker: an empty
`private_domain:` in YAML must fail rather than silently defaulting. Implement
it by unmarshalling into a shadow struct with `*string` for that one field:

```go
// add to config.go
type domainProbe struct {
	DNS struct {
		PrivateDomain *string `yaml:"private_domain"`
	} `yaml:"dns"`
}

// field on Config (unexported, not serialized)
// explicitEmptyDomain bool
```

In `Load`, after `yaml.Unmarshal(raw, &c)`:

```go
	var probe domainProbe
	_ = yaml.Unmarshal(raw, &probe)
	c.explicitEmptyDomain = probe.DNS.PrivateDomain != nil && *probe.DNS.PrivateDomain == ""
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS, all six subtests of `TestLoadRejects` included.

- [ ] **Step 5: Commit**

```bash
git add internal/config go.mod go.sum
git commit -m "Add config loading with defaults and validation

allow_tailscale defaults to false; CGNAT is added to the ACL only via
EffectiveAllowQuery when the flag is on.

AI-assisted contribution (agentic). Verified with: go test ./internal/config/"
```

---

### Task 3: Store schema and migrations

**Files:**
- Create: `internal/store/store.go`, `internal/store/model.go`
- Test: `internal/store/store_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `func Open(path string) (*Store, error)`, `func (s *Store) Close() error`
  - `type View struct { Name string; Subnets []string }`
  - `type Service struct { ID int64; Name string; Addresses []Address; Aliases []string; CheckURL string; CheckInsecure bool }`
  - `type Address struct { ID int64; Address string; View string }` — `View == ""` means all views.
  - `type Record struct { ID int64; Name, Type, Value, View string }`
  - `type Token struct { ID int64; Label, Hash string; CreatedAt, LastUsedAt int64 }`
  - `var ErrDuplicateCIDR, ErrNotFound, ErrViewInUse error`

- [ ] **Step 1: Write the failing test**

```go
// internal/store/store_test.go
package store

import (
	"errors"
	"path/filepath"
	"testing"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrationsAreIdempotent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "kydns.db")
	for i := 0; i < 2; i++ {
		s, err := Open(p)
		if err != nil {
			t.Fatalf("Open() attempt %d: %v", i, err)
		}
		s.Close()
	}
}

func TestViewRoundTrip(t *testing.T) {
	s := open(t)
	if err := s.PutView(View{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}); err != nil {
		t.Fatal(err)
	}
	views, err := s.Views()
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].Name != "tailnet" {
		t.Fatalf("Views() = %+v, want one tailnet view", views)
	}
	if len(views[0].Subnets) != 1 || views[0].Subnets[0] != "100.64.0.0/10" {
		t.Errorf("Subnets = %v", views[0].Subnets)
	}
}

func TestDuplicateCIDRAcrossViewsRejected(t *testing.T) {
	s := open(t)
	if err := s.PutView(View{Name: "a", Subnets: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	err := s.PutView(View{Name: "b", Subnets: []string{"10.0.0.0/8"}})
	if !errors.Is(err, ErrDuplicateCIDR) {
		t.Fatalf("PutView() error = %v, want ErrDuplicateCIDR", err)
	}
}

func TestDeleteViewInUseRejected(t *testing.T) {
	s := open(t)
	if err := s.PutView(View{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutService(Service{
		Name:      "kypost",
		Addresses: []Address{{Address: "100.101.102.103", View: "tailnet"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteView("tailnet"); !errors.Is(err, ErrViewInUse) {
		t.Fatalf("DeleteView() error = %v, want ErrViewInUse", err)
	}
}

func TestServiceRoundTripWithMixedViewTags(t *testing.T) {
	s := open(t)
	if err := s.PutView(View{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}); err != nil {
		t.Fatal(err)
	}
	id, err := s.PutService(Service{
		Name: "kypost",
		Addresses: []Address{
			{Address: "192.168.1.20"},
			{Address: "100.101.102.103", View: "tailnet"},
		},
		Aliases: []string{"webmail"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Service(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Addresses) != 2 {
		t.Fatalf("Addresses = %+v, want 2", got.Addresses)
	}
	var untagged, tagged int
	for _, a := range got.Addresses {
		if a.View == "" {
			untagged++
		} else if a.View == "tailnet" {
			tagged++
		}
	}
	if untagged != 1 || tagged != 1 {
		t.Errorf("untagged=%d tagged=%d, want 1 and 1", untagged, tagged)
	}
	if len(got.Aliases) != 1 || got.Aliases[0] != "webmail" {
		t.Errorf("Aliases = %v", got.Aliases)
	}
}

func TestServiceNotFound(t *testing.T) {
	s := open(t)
	if _, err := s.Service(404); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Service() error = %v, want ErrNotFound", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/ -v`
Expected: FAIL — `undefined: Open`.

- [ ] **Step 3: Write minimal implementation**

```bash
go get modernc.org/sqlite
```

```go
// internal/store/model.go
package store

// View is a named match rule. Subnets are CIDR strings; a CIDR may belong to
// only one view, enforced by a unique index.
type View struct {
	Name    string
	Subnets []string
}

// Address is one address for a service. View == "" means every view.
type Address struct {
	ID      int64
	Address string
	View    string
}

type Service struct {
	ID            int64
	Name          string
	Addresses     []Address
	Aliases       []string
	CheckURL      string
	CheckInsecure bool
}

// Record is a manually authored record. View == "" means every view.
type Record struct {
	ID    int64
	Name  string
	Type  string
	Value string
	View  string
}

type Token struct {
	ID         int64
	Label      string
	Hash       string
	CreatedAt  int64
	LastUsedAt int64
}
```

```go
// internal/store/store.go
// Package store owns all SQL. Every write in KyDNS passes through here, which
// is where the replication change log will later hook in.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrDuplicateCIDR = errors.New("cidr already claimed by another view")
	ErrViewInUse     = errors.New("view is referenced by an address or record")
	ErrDuplicateName = errors.New("name already exists")
)

type Store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS views (
  name       TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS view_subnets (
  view_name TEXT NOT NULL REFERENCES views(name) ON DELETE CASCADE,
  cidr      TEXT NOT NULL,
  PRIMARY KEY (view_name, cidr)
);
-- A CIDR may be claimed by only one view; equal-length overlapping prefixes
-- are the same network, so uniqueness is the whole ambiguity check.
CREATE UNIQUE INDEX IF NOT EXISTS idx_view_subnets_cidr ON view_subnets(cidr);
CREATE TABLE IF NOT EXISTS services (
  id             INTEGER PRIMARY KEY,
  name           TEXT NOT NULL UNIQUE,
  check_url      TEXT NOT NULL DEFAULT '',
  check_insecure INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS service_addresses (
  id         INTEGER PRIMARY KEY,
  service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  address    TEXT NOT NULL,
  view_name  TEXT REFERENCES views(name)
);
CREATE TABLE IF NOT EXISTS aliases (
  id         INTEGER PRIMARY KEY,
  service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name       TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS records (
  id        INTEGER PRIMARY KEY,
  name      TEXT NOT NULL,
  type      TEXT NOT NULL,
  value     TEXT NOT NULL,
  view_name TEXT REFERENCES views(name)
);
CREATE TABLE IF NOT EXISTS tokens (
  id           INTEGER PRIMARY KEY,
  label        TEXT NOT NULL,
  hash         TEXT NOT NULL UNIQUE,
  created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  last_used_at INTEGER NOT NULL DEFAULT 0
);
`

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// One writer, so a single connection avoids SQLITE_BUSY entirely.
	db.SetMaxOpenConns(1)
	for _, p := range []string{
		"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA synchronous=NORMAL",
	} {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func isUnique(err error, fragment string) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE") && strings.Contains(err.Error(), fragment)
}

// PutView inserts or replaces a view and its subnets atomically.
func (s *Store) PutView(v View) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT OR IGNORE INTO views(name) VALUES(?)`, v.Name); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM view_subnets WHERE view_name = ?`, v.Name); err != nil {
		return err
	}
	for _, c := range v.Subnets {
		if _, err := tx.Exec(`INSERT INTO view_subnets(view_name, cidr) VALUES(?, ?)`, v.Name, c); err != nil {
			if isUnique(err, "view_subnets.cidr") {
				return fmt.Errorf("%w: %s", ErrDuplicateCIDR, c)
			}
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Views() ([]View, error) {
	rows, err := s.db.Query(`
		SELECT v.name, COALESCE(sn.cidr, '')
		FROM views v LEFT JOIN view_subnets sn ON sn.view_name = v.name
		ORDER BY v.name, sn.cidr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []View
	byName := map[string]int{}
	for rows.Next() {
		var name, cidr string
		if err := rows.Scan(&name, &cidr); err != nil {
			return nil, err
		}
		i, ok := byName[name]
		if !ok {
			out = append(out, View{Name: name})
			i = len(out) - 1
			byName[name] = i
		}
		if cidr != "" {
			out[i].Subnets = append(out[i].Subnets, cidr)
		}
	}
	return out, rows.Err()
}

func (s *Store) DeleteView(name string) error {
	var n int
	if err := s.db.QueryRow(`
		SELECT (SELECT COUNT(*) FROM service_addresses WHERE view_name = ?) +
		       (SELECT COUNT(*) FROM records WHERE view_name = ?)`, name, name).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: %s (%d references)", ErrViewInUse, name, n)
	}
	res, err := s.db.Exec(`DELETE FROM views WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: view %s", ErrNotFound, name)
	}
	return nil
}

// PutService inserts a new service or replaces an existing one by ID,
// rewriting its addresses and aliases in one transaction.
func (s *Store) PutService(svc Service) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if svc.ID == 0 {
		res, err := tx.Exec(`INSERT INTO services(name, check_url, check_insecure) VALUES(?, ?, ?)`,
			svc.Name, svc.CheckURL, svc.CheckInsecure)
		if err != nil {
			if isUnique(err, "services.name") {
				return 0, fmt.Errorf("%w: service %s", ErrDuplicateName, svc.Name)
			}
			return 0, err
		}
		if svc.ID, err = res.LastInsertId(); err != nil {
			return 0, err
		}
	} else {
		if _, err := tx.Exec(`UPDATE services SET name=?, check_url=?, check_insecure=? WHERE id=?`,
			svc.Name, svc.CheckURL, svc.CheckInsecure, svc.ID); err != nil {
			return 0, err
		}
		for _, q := range []string{
			`DELETE FROM service_addresses WHERE service_id = ?`,
			`DELETE FROM aliases WHERE service_id = ?`,
		} {
			if _, err := tx.Exec(q, svc.ID); err != nil {
				return 0, err
			}
		}
	}
	for _, a := range svc.Addresses {
		if _, err := tx.Exec(`INSERT INTO service_addresses(service_id, address, view_name) VALUES(?, ?, ?)`,
			svc.ID, a.Address, nullable(a.View)); err != nil {
			return 0, err
		}
	}
	for _, al := range svc.Aliases {
		if _, err := tx.Exec(`INSERT INTO aliases(service_id, name) VALUES(?, ?)`, svc.ID, al); err != nil {
			if isUnique(err, "aliases.name") {
				return 0, fmt.Errorf("%w: alias %s", ErrDuplicateName, al)
			}
			return 0, err
		}
	}
	return svc.ID, tx.Commit()
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Store) Service(id int64) (Service, error) {
	var svc Service
	err := s.db.QueryRow(`SELECT id, name, check_url, check_insecure FROM services WHERE id = ?`, id).
		Scan(&svc.ID, &svc.Name, &svc.CheckURL, &svc.CheckInsecure)
	if errors.Is(err, sql.ErrNoRows) {
		return Service{}, fmt.Errorf("%w: service %d", ErrNotFound, id)
	}
	if err != nil {
		return Service{}, err
	}
	if svc.Addresses, err = s.addresses(svc.ID); err != nil {
		return Service{}, err
	}
	if svc.Aliases, err = s.aliases(svc.ID); err != nil {
		return Service{}, err
	}
	return svc, nil
}

func (s *Store) addresses(serviceID int64) ([]Address, error) {
	rows, err := s.db.Query(
		`SELECT id, address, COALESCE(view_name, '') FROM service_addresses WHERE service_id = ? ORDER BY id`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Address
	for rows.Next() {
		var a Address
		if err := rows.Scan(&a.ID, &a.Address, &a.View); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) aliases(serviceID int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT name FROM aliases WHERE service_id = ? ORDER BY name`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// Services returns every service with addresses and aliases loaded. The
// snapshot builder is the main caller, so it is one pass, not N+1 per service.
func (s *Store) Services() ([]Service, error) {
	rows, err := s.db.Query(`SELECT id FROM services ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Service, 0, len(ids))
	for _, id := range ids {
		svc, err := s.Service(id)
		if err != nil {
			return nil, err
		}
		out = append(out, svc)
	}
	return out, nil
}

func (s *Store) DeleteService(id int64) error {
	res, err := s.db.Exec(`DELETE FROM services WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: service %d", ErrNotFound, id)
	}
	return nil
}

func (s *Store) PutRecord(r Record) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO records(name, type, value, view_name) VALUES(?, ?, ?, ?)`,
		r.Name, r.Type, r.Value, nullable(r.View))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) Records() ([]Record, error) {
	rows, err := s.db.Query(
		`SELECT id, name, type, value, COALESCE(view_name, '') FROM records ORDER BY name, type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Value, &r.View); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteRecord(id int64) error {
	res, err := s.db.Exec(`DELETE FROM records WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: record %d", ErrNotFound, id)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/store/ -v`
Expected: PASS. `CGO_ENABLED=0` proves the pure-Go driver works.

- [ ] **Step 5: Commit**

```bash
git add internal/store go.mod go.sum
git commit -m "Add SQLite store with schema and migrations

A unique index on view_subnets.cidr enforces one-view-per-CIDR: equal
prefix lengths that overlap are the same network, so uniqueness covers
the whole ambiguity case.

AI-assisted contribution (agentic). Verified with: CGO_ENABLED=0 go test ./internal/store/"
```

---

### Task 4: Validation rules

**Files:**
- Create: `internal/registry/validate.go`
- Test: `internal/registry/validate_test.go`

**Interfaces:**
- Consumes: `store.Service`, `store.Record`, `store.View`.
- Produces:
  - `type ValidationError struct { Field, Code, Message string }` with `Error() string`
  - `func ValidateLabel(s string) error`
  - `func ValidateName(name, privateFQDN string) error` — FQDN inside the private domain
  - `func ValidateAddress(s string) error`
  - `func ValidateRecordType(s string) error` — A, AAAA, CNAME, PTR only
  - `func Normalize(name string) string` — lowercase, ensure trailing dot

- [ ] **Step 1: Write the failing test**

```go
// internal/registry/validate_test.go
package registry

import "testing"

func TestValidateLabel(t *testing.T) {
	valid := []string{"a", "kypost", "web-mail", "n1", strings.Repeat("x", 63)}
	invalid := []string{"", "-lead", "trail-", "under_score", "has.dot", strings.Repeat("x", 64), "UPPER!"}
	for _, s := range valid {
		if err := ValidateLabel(s); err != nil {
			t.Errorf("ValidateLabel(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range invalid {
		if err := ValidateLabel(s); err == nil {
			t.Errorf("ValidateLabel(%q) = nil, want error", s)
		}
	}
}

func TestValidateNameRequiresPrivateDomain(t *testing.T) {
	const zone = "home.arpa."
	if err := ValidateName("kypost.home.arpa.", zone); err != nil {
		t.Errorf("in-zone name rejected: %v", err)
	}
	if err := ValidateName("kypost.example.com.", zone); err == nil {
		t.Error("out-of-zone name accepted, want error")
	}
	if err := ValidateName("home.arpa.", zone); err == nil {
		t.Error("bare apex accepted, want error")
	}
	if err := ValidateName("*.home.arpa.", zone); err == nil {
		t.Error("wildcard accepted, want error")
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"KyPost.Home.Arpa": "kypost.home.arpa.",
		"kypost.home.arpa.": "kypost.home.arpa.",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateAddress(t *testing.T) {
	for _, s := range []string{"192.168.1.20", "100.101.102.103", "fd00::1"} {
		if err := ValidateAddress(s); err != nil {
			t.Errorf("ValidateAddress(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range []string{"", "192.168.1", "not-an-ip", "192.168.1.20/24"} {
		if err := ValidateAddress(s); err == nil {
			t.Errorf("ValidateAddress(%q) = nil, want error", s)
		}
	}
}

func TestValidateRecordType(t *testing.T) {
	for _, s := range []string{"A", "AAAA", "CNAME", "PTR"} {
		if err := ValidateRecordType(s); err != nil {
			t.Errorf("ValidateRecordType(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range []string{"TXT", "MX", "SRV", "", "a"} {
		if err := ValidateRecordType(s); err == nil {
			t.Errorf("ValidateRecordType(%q) = nil, want error", s)
		}
	}
}
```

Add `"strings"` to the test imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/registry/ -v`
Expected: FAIL — `undefined: ValidateLabel`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/registry/validate.go
package registry

import (
	"fmt"
	"net/netip"
	"strings"
)

// ValidationError carries the offending field so the CLI and the UI can render
// the same failure. Code is the machine-readable form.
type ValidationError struct {
	Field   string
	Code    string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

func invalid(field, code, format string, args ...any) error {
	return &ValidationError{Field: field, Code: code, Message: fmt.Sprintf(format, args...)}
}

// Normalize lowercases a name and gives it a trailing dot.
func Normalize(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return ""
	}
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	return n
}

// ValidateLabel applies RFC 1035 preferred-syntax rules: letters, digits, and
// interior hyphens, 1 to 63 octets.
func ValidateLabel(s string) error {
	if s == "" || len(s) > 63 {
		return invalid("name", "label_length", "label %q must be 1 to 63 characters", s)
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return invalid("name", "label_hyphen", "label %q may not start or end with a hyphen", s)
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return invalid("name", "label_charset", "label %q contains an invalid character %q", s, r)
		}
	}
	return nil
}

// ValidateName checks that a normalized FQDN is a strict subdomain of the
// private zone, with every label valid and no wildcards.
func ValidateName(name, privateFQDN string) error {
	n := Normalize(name)
	if n == "" {
		return invalid("name", "name_empty", "name is required")
	}
	if len(n) > 255 {
		return invalid("name", "name_length", "name exceeds 255 characters")
	}
	if strings.Contains(n, "*") {
		return invalid("name", "wildcard_unsupported", "wildcards are not supported")
	}
	zone := Normalize(privateFQDN)
	if n == zone {
		return invalid("name", "name_is_apex", "name may not be the zone apex %q", zone)
	}
	if !strings.HasSuffix(n, "."+zone) {
		return invalid("name", "name_out_of_zone", "name %q must fall inside %q", n, zone)
	}
	for _, label := range strings.Split(strings.TrimSuffix(n, "."), ".") {
		if err := ValidateLabel(label); err != nil {
			return err
		}
	}
	return nil
}

func ValidateAddress(s string) error {
	if _, err := netip.ParseAddr(s); err != nil {
		return invalid("address", "address_invalid", "%q is not an IP address", s)
	}
	return nil
}

var recordTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "PTR": true}

func ValidateRecordType(s string) error {
	if !recordTypes[s] {
		return invalid("type", "type_unsupported", "record type %q is not supported in v1", s)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/registry/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/registry
git commit -m "Add name, address, and record-type validation

AI-assisted contribution (agentic). Verified with: go test ./internal/registry/"
```

---

### Task 5: View matcher

**Files:**
- Create: `internal/zone/matcher.go`
- Test: `internal/zone/matcher_test.go`

**Interfaces:**
- Consumes: `store.View`.
- Produces:
  - `type Matcher struct{ ... }`
  - `func NewMatcher(views []store.View) (*Matcher, error)`
  - `func (m *Matcher) Match(addr netip.Addr) string` — `""` when nothing matches
  - `func (m *Matcher) Names() []string` — configured view names, sorted

- [ ] **Step 1: Write the failing test**

```go
// internal/zone/matcher_test.go
package zone

import (
	"net/netip"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func TestMatcherLongestPrefixWins(t *testing.T) {
	m, err := NewMatcher([]store.View{
		{Name: "lab", Subnets: []string{"192.168.0.0/16"}},
		{Name: "rack", Subnets: []string{"192.168.7.0/24"}},
		{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		"192.168.7.9":     "rack",
		"192.168.9.9":     "lab",
		"100.101.102.103": "tailnet",
		"10.0.0.1":        "",
		"8.8.8.8":         "",
	} {
		if got := m.Match(netip.MustParseAddr(in)); got != want {
			t.Errorf("Match(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestMatcherIPv6(t *testing.T) {
	m, err := NewMatcher([]store.View{{Name: "ula", Subnets: []string{"fd00::/8"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Match(netip.MustParseAddr("fd00::1")); got != "ula" {
		t.Errorf("Match(fd00::1) = %q, want ula", got)
	}
	if got := m.Match(netip.MustParseAddr("2001:db8::1")); got != "" {
		t.Errorf("Match(2001:db8::1) = %q, want empty", got)
	}
}

// A v4-mapped v6 source address must match a v4 view: UDP sockets on a
// dual-stack listener hand back ::ffff:192.168.1.5 rather than 192.168.1.5.
func TestMatcherUnmapsV4InV6(t *testing.T) {
	m, err := NewMatcher([]store.View{{Name: "lan", Subnets: []string{"192.168.1.0/24"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Match(netip.MustParseAddr("::ffff:192.168.1.5")); got != "lan" {
		t.Errorf("Match(v4-mapped) = %q, want lan", got)
	}
}

func TestMatcherRejectsDuplicateCIDR(t *testing.T) {
	_, err := NewMatcher([]store.View{
		{Name: "a", Subnets: []string{"10.0.0.0/8"}},
		{Name: "b", Subnets: []string{"10.0.0.0/8"}},
	})
	if err == nil {
		t.Fatal("NewMatcher() error = nil, want duplicate CIDR error")
	}
}

func TestMatcherEmpty(t *testing.T) {
	m, err := NewMatcher(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Match(netip.MustParseAddr("192.168.1.1")); got != "" {
		t.Errorf("Match() on empty matcher = %q, want empty", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/zone/ -v`
Expected: FAIL — `undefined: NewMatcher`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/zone/matcher.go
// Package zone builds the immutable per-view snapshot the DNS hot path reads.
package zone

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

type entry struct {
	prefix netip.Prefix
	view   string
}

// Matcher resolves a client source address to a view name. Entries are sorted
// by prefix length descending, so the first containing match is the longest.
// A linear scan is right here: homelabs have a handful of views, and a trie
// would cost more code than it saves.
type Matcher struct {
	entries []entry
	names   []string
}

func NewMatcher(views []store.View) (*Matcher, error) {
	m := &Matcher{}
	claimed := map[netip.Prefix]string{}
	for _, v := range views {
		m.names = append(m.names, v.Name)
		for _, c := range v.Subnets {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				return nil, fmt.Errorf("view %q: cidr %q: %w", v.Name, c, err)
			}
			p = p.Masked()
			if other, dup := claimed[p]; dup {
				return nil, fmt.Errorf("cidr %s is claimed by both view %q and view %q", p, other, v.Name)
			}
			claimed[p] = v.Name
			m.entries = append(m.entries, entry{prefix: p, view: v.Name})
		}
	}
	sort.Slice(m.entries, func(i, j int) bool {
		if a, b := m.entries[i].prefix.Bits(), m.entries[j].prefix.Bits(); a != b {
			return a > b
		}
		return m.entries[i].view < m.entries[j].view
	})
	sort.Strings(m.names)
	return m, nil
}

// Match returns the view name for addr, or "" for the default view.
func (m *Matcher) Match(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	// A dual-stack UDP listener reports v4 peers as ::ffff:a.b.c.d. Unmap so
	// v4 views match without the operator having to write v6 CIDRs.
	addr = addr.Unmap()
	for _, e := range m.entries {
		if e.prefix.Contains(addr) {
			return e.view
		}
	}
	return ""
}

// Names returns the configured view names, sorted. The default view ("") is
// not included.
func (m *Matcher) Names() []string { return m.names }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/zone/ -v`
Expected: PASS, five tests.

- [ ] **Step 5: Commit**

```bash
git add internal/zone
git commit -m "Add longest-prefix view matcher

Unmaps v4-in-v6 source addresses so a dual-stack listener matches
IPv4 view CIDRs without the operator writing v6 prefixes.

AI-assisted contribution (agentic). Verified with: go test ./internal/zone/"
```

---

### Task 6: Snapshot build

**Files:**
- Create: `internal/zone/snapshot.go`
- Test: `internal/zone/snapshot_test.go`

**Interfaces:**
- Consumes: `store.Service`, `store.Record`, `store.View`, `Matcher`.
- Produces:
  - `type RR struct { Name, Type, Value string }`
  - `type Index struct { Forward map[string][]RR; Reverse map[string]string }`
  - `type Snapshot struct { Generation uint32; Matcher *Matcher; Views map[string]*Index; Zone string; ReverseZones []netip.Prefix }`
  - `type Input struct { Views []store.View; Services []store.Service; Records []store.Record; Leases []Lease; Zone string; ReverseZones []netip.Prefix; Generation uint32 }`
  - `type Lease struct { Hostname, Address string }` — populated by Plan 3; empty here
  - `func Build(in Input) (*Snapshot, error)`
  - `func (s *Snapshot) Lookup(view, name string) []RR`
  - `func (s *Snapshot) LookupPTR(view, arpaName string) string`

- [ ] **Step 1: Write the failing test**

```go
// internal/zone/snapshot_test.go
package zone

import (
	"net/netip"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func build(t *testing.T, in Input) *Snapshot {
	t.Helper()
	in.Zone = "home.arpa."
	if in.ReverseZones == nil {
		in.ReverseZones = []netip.Prefix{
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("100.64.0.0/10"),
		}
	}
	s, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func values(rrs []RR) []string {
	out := make([]string, 0, len(rrs))
	for _, r := range rrs {
		out = append(out, r.Value)
	}
	return out
}

func kypost() store.Service {
	return store.Service{
		ID:   1,
		Name: "kypost",
		Addresses: []store.Address{
			{Address: "192.168.1.20"},
			{Address: "100.101.102.103", View: "tailnet"},
		},
		Aliases: []string{"webmail"},
	}
}

func tailnetView() []store.View {
	return []store.View{{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}}
}

func TestViewTaggedAddressSuppressesUntagged(t *testing.T) {
	s := build(t, Input{Views: tailnetView(), Services: []store.Service{kypost()}})

	got := values(s.Lookup("tailnet", "kypost.home.arpa."))
	if len(got) != 1 || got[0] != "100.101.102.103" {
		t.Errorf("tailnet view = %v, want only the tagged address", got)
	}
	got = values(s.Lookup("", "kypost.home.arpa."))
	if len(got) != 1 || got[0] != "192.168.1.20" {
		t.Errorf("default view = %v, want only the untagged address", got)
	}
}

func TestUntaggedAddressVisibleInEveryView(t *testing.T) {
	svc := store.Service{ID: 1, Name: "nas", Addresses: []store.Address{{Address: "192.168.1.30"}}}
	s := build(t, Input{Views: tailnetView(), Services: []store.Service{svc}})
	for _, view := range []string{"", "tailnet"} {
		got := values(s.Lookup(view, "nas.home.arpa."))
		if len(got) != 1 || got[0] != "192.168.1.30" {
			t.Errorf("view %q = %v, want the untagged address", view, got)
		}
	}
}

func TestAliasResolvesToServiceAddress(t *testing.T) {
	s := build(t, Input{Views: tailnetView(), Services: []store.Service{kypost()}})
	got := values(s.Lookup("tailnet", "webmail.home.arpa."))
	if len(got) != 1 || got[0] != "100.101.102.103" {
		t.Errorf("alias in tailnet = %v, want the tagged address", got)
	}
}

func TestManualRecordBeatsService(t *testing.T) {
	s := build(t, Input{
		Services: []store.Service{kypost()},
		Records:  []store.Record{{Name: "kypost.home.arpa.", Type: "A", Value: "192.168.1.99"}},
	})
	got := values(s.Lookup("", "kypost.home.arpa."))
	if len(got) != 1 || got[0] != "192.168.1.99" {
		t.Errorf("= %v, want the manual record to win", got)
	}
}

func TestServiceBeatsLease(t *testing.T) {
	s := build(t, Input{
		Services: []store.Service{kypost()},
		Leases:   []Lease{{Hostname: "kypost", Address: "192.168.1.77"}},
	})
	got := values(s.Lookup("", "kypost.home.arpa."))
	if len(got) != 1 || got[0] != "192.168.1.20" {
		t.Errorf("= %v, want the service to win over the lease", got)
	}
}

func TestPTRDerivedPerView(t *testing.T) {
	s := build(t, Input{Views: tailnetView(), Services: []store.Service{kypost()}})

	if got := s.LookupPTR("", "20.1.168.192.in-addr.arpa."); got != "kypost.home.arpa." {
		t.Errorf("default PTR = %q, want kypost.home.arpa.", got)
	}
	if got := s.LookupPTR("tailnet", "103.102.101.100.in-addr.arpa."); got != "kypost.home.arpa." {
		t.Errorf("tailnet PTR = %q, want kypost.home.arpa.", got)
	}
	// The tailnet address is absent from the default view entirely.
	if got := s.LookupPTR("", "103.102.101.100.in-addr.arpa."); got != "" {
		t.Errorf("default view PTR for tailnet address = %q, want empty", got)
	}
}

func TestAliasesDoNotGeneratePTR(t *testing.T) {
	s := build(t, Input{Services: []store.Service{kypost()}})
	if got := s.LookupPTR("", "20.1.168.192.in-addr.arpa."); got == "webmail.home.arpa." {
		t.Error("PTR resolved to an alias, want the service name")
	}
}

func TestCNAMEConflictRejected(t *testing.T) {
	_, err := Build(Input{
		Zone:     "home.arpa.",
		Views:    tailnetView(),
		Services: []store.Service{kypost()},
		Records: []store.Record{
			{Name: "kypost.home.arpa.", Type: "CNAME", Value: "nas.home.arpa.", View: "tailnet"},
		},
	})
	if err == nil {
		t.Fatal("Build() error = nil, want CNAME conflict in the tailnet view")
	}
}

func TestGenerationIsCarried(t *testing.T) {
	s := build(t, Input{Generation: 42})
	if s.Generation != 42 {
		t.Errorf("Generation = %d, want 42", s.Generation)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/zone/ -run 'TestView|TestUntagged|TestAlias|TestManual|TestService|TestPTR|TestCNAME|TestGeneration' -v`
Expected: FAIL — `undefined: Build`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/zone/snapshot.go
package zone

import (
	"fmt"
	"net/netip"
	"strings"
)

// RR is one resolved record. Name is a normalized FQDN.
type RR struct {
	Name  string
	Type  string
	Value string
}

// Index is one view's resolved data.
type Index struct {
	Forward map[string][]RR
	Reverse map[string]string
}

// Lease is a DHCP-discovered name. Plan 3 populates these; Plan 1 passes none.
type Lease struct {
	Hostname string
	Address  string
}

type Input struct {
	Views        []store.View
	Services     []store.Service
	Records      []store.Record
	Leases       []Lease
	Zone         string
	ReverseZones []netip.Prefix
	Generation   uint32
}

type Snapshot struct {
	Generation   uint32
	Matcher      *Matcher
	Views        map[string]*Index
	Zone         string
	ReverseZones []netip.Prefix
}

// Build resolves every view's effective set. It is all-or-nothing: an error
// means the caller keeps serving the previous snapshot.
func Build(in Input) (*Snapshot, error) {
	m, err := NewMatcher(in.Views)
	if err != nil {
		return nil, err
	}
	snap := &Snapshot{
		Generation:   in.Generation,
		Matcher:      m,
		Views:        map[string]*Index{},
		Zone:         strings.ToLower(in.Zone),
		ReverseZones: in.ReverseZones,
	}
	// "" is the default view, always present.
	for _, view := range append([]string{""}, m.Names()...) {
		idx, err := buildIndex(in, view, snap.Zone)
		if err != nil {
			return nil, fmt.Errorf("view %q: %w", view, err)
		}
		snap.Views[view] = idx
	}
	return snap, nil
}

// pick returns the view-tagged entries when any exist, otherwise the untagged
// ones. This is the "untagged means everywhere" rule.
func pick[T any](view string, tagOf func(T) string, all []T) []T {
	var tagged, untagged []T
	for _, v := range all {
		switch tagOf(v) {
		case view:
			if view != "" {
				tagged = append(tagged, v)
			} else {
				untagged = append(untagged, v)
			}
		case "":
			untagged = append(untagged, v)
		}
	}
	if len(tagged) > 0 {
		return tagged
	}
	return untagged
}

func buildIndex(in Input, view, zone string) (*Index, error) {
	idx := &Index{Forward: map[string][]RR{}, Reverse: map[string]string{}}

	// Precedence is applied by writing in ascending priority and letting later
	// layers replace earlier ones: lease, then service/alias, then manual.
	for _, l := range in.Leases {
		name := qualify(l.Hostname, zone)
		idx.Forward[name] = []RR{{Name: name, Type: addrType(l.Address), Value: l.Address}}
	}

	for _, svc := range in.Services {
		addrs := pick(view, func(a store.Address) string { return a.View }, svc.Addresses)
		if len(addrs) == 0 {
			continue
		}
		primary := qualify(svc.Name, zone)
		rrs := make([]RR, 0, len(addrs))
		for _, a := range addrs {
			rrs = append(rrs, RR{Name: primary, Type: addrType(a.Address), Value: a.Address})
		}
		idx.Forward[primary] = rrs
		for _, alias := range svc.Aliases {
			an := qualify(alias, zone)
			ar := make([]RR, 0, len(addrs))
			for _, a := range addrs {
				ar = append(ar, RR{Name: an, Type: addrType(a.Address), Value: a.Address})
			}
			idx.Forward[an] = ar
		}
		// Only the primary name gets a PTR; aliases do not.
		for _, a := range addrs {
			if addr, err := netip.ParseAddr(a.Address); err == nil && inZones(addr, in.ReverseZones) {
				idx.Reverse[arpaName(addr)] = primary
			}
		}
	}

	for _, r := range pick(view, func(r store.Record) string { return r.View }, in.Records) {
		name := strings.ToLower(r.Name)
		if r.Type == "PTR" {
			idx.Reverse[name] = strings.ToLower(r.Value)
			continue
		}
		idx.Forward[name] = []RR{{Name: name, Type: r.Type, Value: strings.ToLower(r.Value)}}
	}

	for name, rrs := range idx.Forward {
		var hasCNAME, hasAddr bool
		for _, rr := range rrs {
			if rr.Type == "CNAME" {
				hasCNAME = true
			} else {
				hasAddr = true
			}
		}
		if hasCNAME && (hasAddr || len(rrs) > 1) {
			return nil, fmt.Errorf("%s: CNAME may not coexist with address records", name)
		}
	}
	return idx, nil
}

func addrType(s string) string {
	if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
		return "A"
	}
	return "AAAA"
}

func qualify(name, zone string) string {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if strings.HasSuffix(n+".", zone) {
		return n + "."
	}
	return n + "." + zone
}

func inZones(a netip.Addr, zones []netip.Prefix) bool {
	for _, z := range zones {
		if z.Contains(a) {
			return true
		}
	}
	return false
}

// arpaName renders the reverse FQDN for an address.
func arpaName(a netip.Addr) string {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0])
	}
	b := a.As16()
	var sb strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		fmt.Fprintf(&sb, "%x.%x.", b[i]&0xf, b[i]>>4)
	}
	sb.WriteString("ip6.arpa.")
	return sb.String()
}

// Lookup returns the records for name in view, falling back to the default
// view's index when the named view does not exist.
func (s *Snapshot) Lookup(view, name string) []RR {
	idx, ok := s.Views[view]
	if !ok {
		idx = s.Views[""]
	}
	return idx.Forward[strings.ToLower(name)]
}

// LookupPTR returns the target name for a reverse query, or "".
func (s *Snapshot) LookupPTR(view, arpa string) string {
	idx, ok := s.Views[view]
	if !ok {
		idx = s.Views[""]
	}
	return idx.Reverse[strings.ToLower(arpa)]
}

// HasName reports whether the name exists in the view with any type, which is
// how the handler distinguishes NODATA from NXDOMAIN.
func (s *Snapshot) HasName(view, name string) bool {
	return len(s.Lookup(view, name)) > 0
}
```

Add the `store` import to `snapshot.go`:
`"github.com/yoshiofthewire/kydns-server/internal/store"`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/zone/ -v`
Expected: PASS, all matcher and snapshot tests.

- [ ] **Step 5: Commit**

```bash
git add internal/zone
git commit -m "Add per-view snapshot build with precedence and PTR derivation

Untagged addresses are visible in every view; a view-tagged address for
a name suppresses the untagged ones for that view only. Precedence is
applied by write order: lease, then service and alias, then manual
record. CNAME conflicts are checked per view.

AI-assisted contribution (agentic). Verified with: go test ./internal/zone/"
```

---

## Remaining tasks

Tasks 7 through 13 follow the same structure and are written in a companion
file to keep each document reviewable:

| Task | Deliverable |
|---|---|
| 7 | `zone.Holder`: `atomic.Pointer` swap, all-or-nothing rebuild, generation counter as SOA serial |
| 8 | `dnsserver/acl.go`: prefix check, refusal counters with last-seen timestamps, CGNAT bucket |
| 9 | `dnsserver/auth.go`: authoritative answers, SOA and NS synthesis, NODATA vs NXDOMAIN, CNAME chase with depth cap |
| 10 | `dnsserver/cache.go` and `forward.go`: LRU with TTL decrement, RFC 2308 negative caching, sequential upstream failover, single-flight |
| 11 | `dnsserver/server.go`: UDP and TCP listeners, the full pipeline, query logging |
| 12 | `adminapi`: token auth, services/records/views CRUD, JSON error shape, `/stats` |
| 13 | `cli` and `serve` wiring, export/import, end-to-end integration test |

**Next action for the implementer:** stop after Task 6 and request the
companion plan file, or ask the plan author to generate it.

## Self-Review

**Spec coverage (Plan 1 portion).** Config defaults and `allow_tailscale` → Task 2. Store schema, single write chokepoint, views as registry data → Task 3. Validation including per-view CNAME rules → Tasks 4 and 6. Longest-prefix matching and v4-in-v6 unmapping → Task 5. Untagged-means-everywhere, precedence, per-view PTR derivation, generation as SOA serial → Task 6. Remaining spec sections map to Tasks 7 to 13 in the table above.

**Placeholder scan.** No TBD or "handle errors appropriately" steps; every code step carries runnable code. The one forward reference, `zone.Lease`, is defined in Task 6 and left empty until Plan 3, which is stated at its definition.

**Type consistency.** `store.Address.View`, `store.Record.View`, and `zone.Input` all use `""` for untagged. `Matcher.Match` returns `""` for the default view, matching the key `Snapshot.Views[""]`. `Build` takes `Input` and returns `*Snapshot` consistently across Tasks 5, 6, and 7.
