# KyDNS Blacklists Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-out DNS blackhole filtering — built-in and custom lists, one-off allow/deny rules, and a global toggle — that applies only to forwarded public names and can never blackhole a local service.

**Architecture:** A new `internal/policy` package owns normalization, list parsing, the immutable decision snapshot, the HTTPS fetcher, the refresh scheduler, and the validating service layer. It mirrors `internal/zone`: a `Holder` builds a complete `*Snapshot` and atomically swaps it, and the DNS hot path reads it with no lock. `dnsserver` gains one small `PolicyDecider` interface, consulted **after** the authoritative lookup returns nil and **before** the forwarder, so a blocked name never reaches an upstream and a local name never reaches the policy.

**Tech Stack:** Go 1.26.5, `modernc.org/sqlite` (pure Go, no cgo), `github.com/miekg/dns`, `html/template`, `gopkg.in/yaml.v3`. One dependency promotion: `golang.org/x/net/idna` (already an indirect dependency) becomes direct.

## Global Constraints

- **Resolution order is fixed and is the whole point of the feature:** authoritative KyDNS data → one-off deny → one-off allow → enabled list → forwarder. A local service or record can never be blackholed by a public list.
- **A blocked query is never sent upstream.** The block is decided before `Forwarder.Resolve` is called.
- Blocked names return **local `NXDOMAIN` with the `AA` bit clear**. The negative TTL comes from the configured block TTL, default **60** seconds, carried on a synthesized SOA whose owner is the queried name.
- **A list outage must not make DNS fail.** Refresh is transactional: parse and validate the complete download, then replace the snapshot. A failed download or parse keeps the last known-good snapshot and marks it stale.
- Downloads are **HTTPS only, with certificate verification**, a bounded body size, connect and total timeouts, and a redirect limit. Redirects to non-HTTPS are refused.
- **KyDNS sends no query names, client addresses, or identifying headers to list hosts.** The only request headers are `User-Agent: kydns`, `If-None-Match`, and `If-Modified-Since`.
- **Never log downloaded content, list URLs containing credentials, client IPs, or query names by default.** Query logging stays behind `dns.log_queries`, and the client IP stays behind its own separate `dns.log_client_ip`.
- Exports carry **policy settings, list definitions, and one-off rules only** — never downloaded list bodies, never credentials.
- Built-in lists ship as a **versioned embedded manifest**. This release ships exactly one: StevenBlack unified hosts (MIT).
- Filtering does **not** vary by client view in this plan. Per-view policy is a future feature.
- `CGO_ENABLED=0` must keep building. The only `go.mod` change permitted is promoting `golang.org/x/net` from indirect to direct.
- Every task leaves `go build ./...`, `go vet ./...`, `gofmt -l .`, and `CGO_ENABLED=0 go test ./...` clean.
- House style: YAGNI, short meaningful comments, no comment block defending why code is not wrong.

## File Structure

| File | Responsibility |
|---|---|
| `internal/policy/normalize.go` | `Normalize` — lower case, strip trailing dot, IDNA to ASCII, reject invalid |
| `internal/policy/set.go` | `Set` — immutable suffix-matching domain set |
| `internal/policy/parse.go` | `Parse` — `domains`, `hosts`, `adblock` formats; skip counting |
| `internal/policy/snapshot.go` | `Snapshot`, `Decision`, `Build`, `Decide` — precedence lives here |
| `internal/policy/holder.go` | `Holder` — atomic swap, counters, implements `dnsserver.PolicyDecider` |
| `internal/policy/fetch.go` | `Fetcher` — bounded verified HTTPS download with cache validators |
| `internal/policy/manifest.go` + `builtin.json` | Embedded versioned built-in manifest and seeding |
| `internal/policy/refresher.go` | 90-second scheduler; transactional per-list refresh |
| `internal/policy/service.go` | Validation and the API both transports call |
| `internal/store/blacklist.go` | All blacklist SQL |
| `internal/store/model.go` | `BlacklistSettings`, `BlacklistList`, `BlacklistRule` |
| `internal/store/store.go` | Three new tables in the `schema` block |
| `internal/dnsserver/server.go` | `PolicyDecider`, the block reply, the `policy` log field |
| `internal/adminapi/blacklists.go` | The eight blacklist endpoints |
| `internal/adminapi/api.go` | Export/import gains the blacklist document |
| `internal/cli/blacklist.go` | `kydns blacklist` command family |
| `internal/web/blacklists.go` + `templates/blacklists.html` | The Blacklists tab |
| `internal/app/serve.go` | Wiring |
| `README.md`, `DESGINE.md`, `LOGGING.md`, `SECURITY.md`, `AGENTS.md` | Documentation |

---

## Task 1: Domain normalization and suffix matching

**Files:**
- Create: `internal/policy/normalize.go`
- Create: `internal/policy/set.go`
- Create: `internal/policy/normalize_test.go`
- Create: `internal/policy/set_test.go`
- Modify: `go.mod`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `policy.Normalize(name string) (string, error)` — canonical form: lower case, no trailing dot, IDNA-ASCII
  - `policy.NewSet(domains []string) *Set` — `domains` must already be normalized
  - `(*policy.Set).Match(name string) bool` — exact or parent-domain match on an already-normalized name
  - `(*policy.Set).Len() int`

- [ ] **Step 1: Write the failing tests**

Create `internal/policy/normalize_test.go`:

```go
package policy

import "testing"

func TestNormalizeCanonicalizes(t *testing.T) {
	cases := map[string]string{
		"ads.example":      "ads.example",
		"ADS.Example":      "ads.example",
		"ads.example.":     "ads.example",
		"  ads.example  ":  "ads.example",
		"a.b.c.example":    "a.b.c.example",
		"bücher.example":   "xn--bcher-kva.example",
		"xn--bcher-kva.ex": "xn--bcher-kva.ex",
	}
	for in, want := range cases {
		got, err := Normalize(in)
		if err != nil {
			t.Errorf("Normalize(%q) errored: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeRejectsJunk(t *testing.T) {
	for _, in := range []string{
		"", ".", "..", "example..com", "-ads.example", "ads-.example",
		"ads.example/path", "ads example", "*.example", "192.168.1.1",
		"2001:db8::1", "http://ads.example",
	} {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q, want an error", in, got)
		}
	}
}

func TestNormalizeRejectsOverlongNames(t *testing.T) {
	long := ""
	for i := 0; i < 10; i++ {
		long += "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz."
	}
	if _, err := Normalize(long + "example"); err == nil {
		t.Error("Normalize() accepted a name over 253 characters")
	}
	if _, err := Normalize("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz1234.example"); err == nil {
		t.Error("Normalize() accepted a label over 63 characters")
	}
}
```

Create `internal/policy/set_test.go`:

```go
package policy

import "testing"

func TestSetMatchesNameAndSubdomains(t *testing.T) {
	s := NewSet([]string{"ads.example", "tracker.test"})
	for _, name := range []string{"ads.example", "a.ads.example", "deep.a.ads.example", "tracker.test"} {
		if !s.Match(name) {
			t.Errorf("Match(%q) = false, want true", name)
		}
	}
}

// The suffix boundary is a label boundary, not a string suffix. This is the
// single most important property in the whole feature.
func TestSetDoesNotMatchAcrossLabelBoundaries(t *testing.T) {
	s := NewSet([]string{"ads.example"})
	for _, name := range []string{"badads.example", "example", "ads.example.evil", "notads.example"} {
		if s.Match(name) {
			t.Errorf("Match(%q) = true, want false", name)
		}
	}
}

func TestSetLenDeduplicates(t *testing.T) {
	s := NewSet([]string{"ads.example", "ads.example", "tracker.test"})
	if s.Len() != 2 {
		t.Errorf("Len() = %d, want 2", s.Len())
	}
}

func TestEmptySetMatchesNothing(t *testing.T) {
	if NewSet(nil).Match("ads.example") {
		t.Error("an empty set matched")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/policy/...`
Expected: FAIL — the package does not exist yet.

- [ ] **Step 3: Add the dependency**

Run: `go get golang.org/x/net@v0.57.0`
Expected: `golang.org/x/net v0.57.0` moves out of the indirect block in `go.mod`.

- [ ] **Step 4: Write `internal/policy/normalize.go`**

```go
// Package policy decides whether a forwarded name is blocked. It never sees
// authoritative names: the DNS pipeline consults it only after the
// authoritative lookup declines, so a local service cannot be blackholed.
package policy

import (
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// maxName and maxLabel are the DNS wire limits in presentation form, without
// the trailing dot.
const (
	maxName  = 253
	maxLabel = 63
)

var errNotADomain = errors.New("not a domain name")

// Normalize returns the canonical form of a domain: lower case, no trailing
// dot, IDNA converted to ASCII. Anything that is not a usable domain name is
// rejected rather than silently coerced, so a typo in a rule fails loudly
// instead of matching nothing forever.
func Normalize(name string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".")
	if n == "" {
		return "", errNotADomain
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return "", errNotADomain // an IP address is not a name to block
	}
	n, err := idna.Lookup.ToASCII(n)
	if err != nil {
		return "", errNotADomain
	}
	if len(n) > maxName || !strings.Contains(n, ".") {
		return "", errNotADomain
	}
	for _, label := range strings.Split(n, ".") {
		if err := validLabel(label); err != nil {
			return "", err
		}
	}
	return n, nil
}

func validLabel(s string) error {
	if s == "" || len(s) > maxLabel {
		return errNotADomain
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return errNotADomain
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return errNotADomain
		}
	}
	return nil
}
```

- [ ] **Step 5: Write `internal/policy/set.go`**

```go
package policy

import "strings"

// Set is an immutable suffix-matching domain set. A rule for ads.example
// matches that name and its subdomains, but never badads.example: the walk
// only ever cuts at a label boundary.
type Set struct{ m map[string]struct{} }

// NewSet builds a set from already-normalized domains.
func NewSet(domains []string) *Set {
	m := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		m[d] = struct{}{}
	}
	return &Set{m: m}
}

// Match reports whether name, itself already normalized, is in the set or is a
// subdomain of something in it.
func (s *Set) Match(name string) bool {
	if s == nil || len(s.m) == 0 {
		return false
	}
	for {
		if _, ok := s.m[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
}

func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.m)
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/policy/... -v`
Expected: PASS, all eight tests.

- [ ] **Step 7: Verify the whole tree still builds clean**

Run: `go build ./... && go vet ./... && gofmt -l . && CGO_ENABLED=0 go test ./...`
Expected: no output from `gofmt -l .`, all tests pass.

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum internal/policy/
git commit -m "feat(policy): domain normalization and suffix matching"
```

---

## Task 2: List parsers for the three formats

**Files:**
- Create: `internal/policy/parse.go`
- Create: `internal/policy/parse_test.go`

**Interfaces:**
- Consumes: `policy.Normalize` from Task 1.
- Produces:
  - `policy.FormatDomains`, `policy.FormatHosts`, `policy.FormatAdblock` — the three `string` constants `"domains"`, `"hosts"`, `"adblock"`
  - `policy.ValidFormat(string) bool`
  - `policy.ParseResult{Domains []string; Skipped int}` — `Domains` normalized, deduplicated, sorted
  - `policy.Parse(r io.Reader, format string) (ParseResult, error)`

- [ ] **Step 1: Write the failing test**

Create `internal/policy/parse_test.go`:

```go
package policy

import (
	"strings"
	"testing"
)

func TestParseDomainsFormat(t *testing.T) {
	in := `
# a comment
ads.example

  Tracker.Test  
192.168.1.1
not a domain
ads.example
`
	got, err := Parse(strings.NewReader(in), FormatDomains)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ads.example", "tracker.test"}
	if strings.Join(got.Domains, ",") != strings.Join(want, ",") {
		t.Errorf("Domains = %v, want %v", got.Domains, want)
	}
	// The IP address and the malformed line are counted, not silently dropped.
	if got.Skipped != 2 {
		t.Errorf("Skipped = %d, want 2", got.Skipped)
	}
}

func TestParseHostsFormat(t *testing.T) {
	in := `
127.0.0.1 localhost
127.0.0.1 localhost.localdomain
255.255.255.255 broadcasthost
::1 ip6-localhost ip6-loopback
0.0.0.0 ads.example
0.0.0.0 a.test b.test
0.0.0.0
garbage line
`
	got, err := Parse(strings.NewReader(in), FormatHosts)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.test", "ads.example", "b.test"}
	if strings.Join(got.Domains, ",") != strings.Join(want, ",") {
		t.Errorf("Domains = %v, want %v", got.Domains, want)
	}
	if got.Skipped == 0 {
		t.Error("Skipped = 0, want the localhost, broadcast and malformed lines counted")
	}
}

func TestParseAdblockFormat(t *testing.T) {
	in := `
! a comment
||ads.example^
||tracker.test^
@@||good.example^
||ads.example^$third-party
example.com##.banner
/some/path
||bad_
`
	got, err := Parse(strings.NewReader(in), FormatAdblock)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ads.example", "tracker.test"}
	if strings.Join(got.Domains, ",") != strings.Join(want, ",") {
		t.Errorf("Domains = %v, want %v", got.Domains, want)
	}
	// An exception rule is not an allow rule: it is unsupported and skipped.
	if got.Skipped < 4 {
		t.Errorf("Skipped = %d, want the exception, modifier, cosmetic and path rules counted", got.Skipped)
	}
}

func TestParseRejectsAnUnknownFormat(t *testing.T) {
	if _, err := Parse(strings.NewReader("ads.example"), "regex"); err == nil {
		t.Error("Parse() accepted an unknown format")
	}
}

// The ceiling is exercised through parseLimit rather than by building a
// two-million-line fixture, which would cost seconds and a gigabyte to prove
// one comparison.
func TestParseRefusesAListPastTheEntryCeiling(t *testing.T) {
	in := "a.example\nb.example\nc.example\nd.example\n"
	if _, err := parseLimit(strings.NewReader(in), FormatDomains, 2); err == nil {
		t.Error("parseLimit() accepted a list past the entry ceiling")
	}
}

func TestValidFormat(t *testing.T) {
	for _, f := range []string{FormatDomains, FormatHosts, FormatAdblock} {
		if !ValidFormat(f) {
			t.Errorf("ValidFormat(%q) = false", f)
		}
	}
	if ValidFormat("regex") {
		t.Error("ValidFormat(\"regex\") = true")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/policy/ -run TestParse`
Expected: FAIL with "undefined: Parse".

- [ ] **Step 3: Write `internal/policy/parse.go`**

```go
package policy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// The three list formats KyDNS ingests.
const (
	FormatDomains = "domains"
	FormatHosts   = "hosts"
	FormatAdblock = "adblock"
)

// maxEntries bounds a parsed list. Downloaded lists are untrusted input, and
// the fetcher's byte ceiling alone does not bound the map this builds.
const maxEntries = 1 << 21

// maxLineBytes bounds one line, so a single unterminated line cannot be read
// into memory without limit.
const maxLineBytes = 4096

// localNames are the hosts-file entries every list carries and no resolver
// should ever blackhole.
var localNames = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true,
	"broadcasthost": true, "ip6-localhost": true, "ip6-loopback": true,
	"ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true,
}

func ValidFormat(f string) bool {
	return f == FormatDomains || f == FormatHosts || f == FormatAdblock
}

// ParseResult is one parsed list. Skipped counts every line that produced no
// domain, so the UI can show that a list loaded but half of it was unusable.
type ParseResult struct {
	Domains []string
	Skipped int
}

// Parse reads a list body. It never returns a partial result: a caller that
// gets an error keeps its previous snapshot.
func Parse(r io.Reader, format string) (ParseResult, error) {
	return parseLimit(r, format, maxEntries)
}

// parseLimit is Parse with an injectable ceiling, so the ceiling can be tested
// without building a two-million-line fixture.
func parseLimit(r io.Reader, format string, max int) (ParseResult, error) {
	if !ValidFormat(format) {
		return ParseResult{}, fmt.Errorf("unknown list format %q", format)
	}
	var res ParseResult
	seen := map[string]struct{}{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxLineBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue // comments and blanks are not failures
		}
		names, ok := lineDomains(line, format)
		if !ok || len(names) == 0 {
			res.Skipped++
			continue
		}
		added := 0
		for _, raw := range names {
			n, err := Normalize(raw)
			if err != nil || localNames[n] {
				continue
			}
			added++
			if _, dup := seen[n]; dup {
				continue
			}
			seen[n] = struct{}{}
			if len(seen) > max {
				return ParseResult{}, errors.New("list exceeds the entry ceiling")
			}
		}
		if added == 0 {
			res.Skipped++
		}
	}
	if err := sc.Err(); err != nil {
		return ParseResult{}, err
	}
	res.Domains = make([]string, 0, len(seen))
	for n := range seen {
		res.Domains = append(res.Domains, n)
	}
	sort.Strings(res.Domains)
	return res, nil
}

// lineDomains extracts the candidate names from one line. It returns false for
// a line the format cannot represent at all.
func lineDomains(line, format string) ([]string, bool) {
	switch format {
	case FormatDomains:
		if strings.ContainsAny(line, " \t/") {
			return nil, false
		}
		return []string{line}, true

	case FormatHosts:
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, false
		}
		// The first field is the sink address; everything after it is a name.
		return fields[1:], true

	case FormatAdblock:
		// Only the plain domain-anchored form is supported. Exception rules,
		// modifiers, cosmetic filters and path rules are not domain filtering,
		// so they are skipped rather than half-honored.
		if !strings.HasPrefix(line, "||") || strings.ContainsAny(line, "$/*#@") {
			return nil, false
		}
		rule := strings.TrimSuffix(strings.TrimPrefix(line, "||"), "^")
		if rule == "" || strings.Contains(rule, "^") {
			return nil, false
		}
		return []string{rule}, true
	}
	return nil, false
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/policy/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/parse.go internal/policy/parse_test.go
git commit -m "feat(policy): parse domains, hosts and adblock list formats"
```

---

## Task 3: Blacklist storage

**Files:**
- Modify: `internal/store/store.go:23-76` — the `schema` constant
- Modify: `internal/store/model.go` — three new structs
- Create: `internal/store/blacklist.go`
- Create: `internal/store/blacklist_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces, on `*store.Store`:
  - `BlacklistSettings() (BlacklistSettings, error)`, `SetBlacklistSettings(BlacklistSettings) error`
  - `BlacklistLists() ([]BlacklistList, error)` — snapshots loaded, for the policy rebuild
  - `BlacklistListMetas() ([]BlacklistList, error)` — snapshots omitted, for the UI and API
  - `BlacklistListByID(id int64) (BlacklistList, error)` — snapshot loaded
  - `PutBlacklistList(BlacklistList) (int64, error)` — writes the definition only, never the snapshot
  - `SetBlacklistSnapshot(id int64, domains []string, skipped int, etag, lastModified string, at int64) error`
  - `SetBlacklistError(id int64, msg string, at int64) error`
  - `DeleteBlacklistList(id int64) error`
  - `BlacklistRules() ([]BlacklistRule, error)`, `PutBlacklistRule(BlacklistRule) (int64, error)`, `DeleteBlacklistRule(id int64) error`
  - `ReplaceBlacklist(BlacklistSettings, []BlacklistList, []BlacklistRule) error`

**Note for the implementer:** `Open` runs the whole `schema` constant on every open, and every statement in it is `CREATE TABLE IF NOT EXISTS`. New *tables* therefore need no entry in `migrations` — that list exists only for `ALTER`. Do not add one.

- [ ] **Step 1: Write the failing test**

Create `internal/store/blacklist_test.go`:

```go
package store

import (
	"errors"
	"testing"
)

func TestBlacklistDefaultsAreOn(t *testing.T) {
	s := open(t)
	got, err := s.BlacklistSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.BlockTTL != 60 {
		t.Errorf("BlacklistSettings() = %+v, want filtering on with a 60s block TTL", got)
	}
}

func TestBlacklistSettingsRoundTrip(t *testing.T) {
	s := open(t)
	if err := s.SetBlacklistSettings(BlacklistSettings{Enabled: false, BlockTTL: 30}); err != nil {
		t.Fatal(err)
	}
	got, err := s.BlacklistSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled || got.BlockTTL != 30 {
		t.Errorf("BlacklistSettings() = %+v, want {false 30}", got)
	}
}

func TestBlacklistListRoundTripsAndKeepsItsSnapshot(t *testing.T) {
	s := open(t)
	id, err := s.PutBlacklistList(BlacklistList{
		Name: "steven-black", URL: "https://lists.example/hosts",
		Format: "hosts", Enabled: true, Builtin: true,
		Description: "unified hosts", IntervalSeconds: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetBlacklistSnapshot(id, []string{"ads.example", "tracker.test"}, 7, "W/\"abc\"", "Mon, 01 Jan 2026 00:00:00 GMT", 1000); err != nil {
		t.Fatal(err)
	}

	got, err := s.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Snapshot) != 2 || got.Snapshot[0] != "ads.example" {
		t.Errorf("Snapshot = %v, want the two stored domains", got.Snapshot)
	}
	if got.EntryCount != 2 || got.SkippedCount != 7 || got.LastOKAt != 1000 || got.LastError != "" {
		t.Errorf("metadata = %+v, want 2 entries, 7 skipped, ok at 1000, no error", got)
	}
	if got.ETag != "W/\"abc\"" || got.LastModified == "" {
		t.Errorf("validators = %q / %q, want both stored", got.ETag, got.LastModified)
	}

	// An edit to the definition must not disturb the downloaded snapshot.
	got.Enabled = false
	got.Description = "renamed"
	if _, err := s.PutBlacklistList(got); err != nil {
		t.Fatal(err)
	}
	after, err := s.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Snapshot) != 2 || after.EntryCount != 2 || after.LastOKAt != 1000 {
		t.Errorf("after a definition edit = %+v, want the snapshot untouched", after)
	}
	if after.Enabled || after.Description != "renamed" {
		t.Errorf("after a definition edit = %+v, want the edit applied", after)
	}
}

// A failed refresh records the error and the attempt, and keeps the last good
// snapshot serving.
func TestSetBlacklistErrorKeepsTheSnapshot(t *testing.T) {
	s := open(t)
	id, err := s.PutBlacklistList(BlacklistList{Name: "l", URL: "https://e/x", Format: "domains", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetBlacklistSnapshot(id, []string{"ads.example"}, 0, "", "", 100); err != nil {
		t.Fatal(err)
	}
	if err := s.SetBlacklistError(id, "dial tcp: i/o timeout", 200); err != nil {
		t.Fatal(err)
	}
	got, err := s.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Snapshot) != 1 || got.LastOKAt != 100 {
		t.Errorf("= %+v, want the last good snapshot retained", got)
	}
	if got.LastError == "" || got.LastAttemptAt != 200 {
		t.Errorf("= %+v, want the failure recorded", got)
	}
}

func TestBlacklistListMetasOmitSnapshots(t *testing.T) {
	s := open(t)
	id, err := s.PutBlacklistList(BlacklistList{Name: "l", URL: "https://e/x", Format: "domains", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetBlacklistSnapshot(id, []string{"ads.example"}, 0, "", "", 100); err != nil {
		t.Fatal(err)
	}
	metas, err := s.BlacklistListMetas()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 1 || metas[0].Snapshot != nil || metas[0].EntryCount != 1 {
		t.Errorf("BlacklistListMetas() = %+v, want the count without the body", metas)
	}
}

func TestDuplicateListNameRejected(t *testing.T) {
	s := open(t)
	l := BlacklistList{Name: "dup", URL: "https://e/x", Format: "domains", Enabled: true}
	if _, err := s.PutBlacklistList(l); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutBlacklistList(l); !errors.Is(err, ErrDuplicateName) {
		t.Errorf("second PutBlacklistList = %v, want ErrDuplicateName", err)
	}
}

// One domain may hold at most one rule, which is how a rule that is both
// allowed and denied is refused at the schema level rather than by a check
// that some future caller could skip.
func TestConflictingRuleRejected(t *testing.T) {
	s := open(t)
	if _, err := s.PutBlacklistRule(BlacklistRule{Kind: "deny", Domain: "ads.example"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutBlacklistRule(BlacklistRule{Kind: "allow", Domain: "ads.example"}); !errors.Is(err, ErrDuplicateName) {
		t.Errorf("conflicting rule = %v, want ErrDuplicateName", err)
	}
	if _, err := s.PutBlacklistRule(BlacklistRule{Kind: "deny", Domain: "ads.example"}); !errors.Is(err, ErrDuplicateName) {
		t.Errorf("duplicate rule = %v, want ErrDuplicateName", err)
	}
}

func TestRuleDelete(t *testing.T) {
	s := open(t)
	id, err := s.PutBlacklistRule(BlacklistRule{Kind: "allow", Domain: "good.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteBlacklistRule(id); err != nil {
		t.Fatal(err)
	}
	rules, err := s.BlacklistRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Errorf("BlacklistRules() = %v, want empty", rules)
	}
	if err := s.DeleteBlacklistRule(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete = %v, want ErrNotFound", err)
	}
}

// Replace preserves a surviving list's downloaded body, so importing a backup
// does not force every list to re-download.
func TestReplaceBlacklistPreservesSnapshotsByURL(t *testing.T) {
	s := open(t)
	id, err := s.PutBlacklistList(BlacklistList{Name: "keep", URL: "https://e/x", Format: "domains", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetBlacklistSnapshot(id, []string{"ads.example"}, 0, "etag", "", 100); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceBlacklist(
		BlacklistSettings{Enabled: true, BlockTTL: 60},
		[]BlacklistList{{Name: "keep-renamed", URL: "https://e/x", Format: "domains", Enabled: true}},
		[]BlacklistRule{{Kind: "deny", Domain: "bad.example"}},
	); err != nil {
		t.Fatal(err)
	}
	lists, err := s.BlacklistLists()
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 1 || lists[0].Name != "keep-renamed" {
		t.Fatalf("BlacklistLists() = %+v, want the imported definition", lists)
	}
	if len(lists[0].Snapshot) != 1 || lists[0].ETag != "etag" || lists[0].LastOKAt != 100 {
		t.Errorf("= %+v, want the prior snapshot preserved by URL", lists[0])
	}
	rules, err := s.BlacklistRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Domain != "bad.example" {
		t.Errorf("BlacklistRules() = %+v, want only the imported rule", rules)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/store/ -run Blacklist`
Expected: FAIL with "undefined: BlacklistSettings".

- [ ] **Step 3: Add the schema**

Append to the `schema` constant in `internal/store/store.go`, before the closing backtick:

```sql
CREATE TABLE IF NOT EXISTS blacklist_settings (
  id        INTEGER PRIMARY KEY CHECK (id = 1),
  enabled   INTEGER NOT NULL DEFAULT 1,
  block_ttl INTEGER NOT NULL DEFAULT 60
);
INSERT OR IGNORE INTO blacklist_settings(id, enabled, block_ttl) VALUES(1, 1, 60);
CREATE TABLE IF NOT EXISTS blacklist_lists (
  id               INTEGER PRIMARY KEY,
  name             TEXT NOT NULL UNIQUE,
  url              TEXT NOT NULL,
  format           TEXT NOT NULL DEFAULT 'domains',
  description      TEXT NOT NULL DEFAULT '',
  enabled          INTEGER NOT NULL DEFAULT 1,
  builtin          INTEGER NOT NULL DEFAULT 0,
  interval_seconds INTEGER NOT NULL DEFAULT 86400,
  last_attempt_at  INTEGER NOT NULL DEFAULT 0,
  last_ok_at       INTEGER NOT NULL DEFAULT 0,
  last_error       TEXT NOT NULL DEFAULT '',
  etag             TEXT NOT NULL DEFAULT '',
  last_modified    TEXT NOT NULL DEFAULT '',
  entry_count      INTEGER NOT NULL DEFAULT 0,
  skipped_count    INTEGER NOT NULL DEFAULT 0,
  snapshot         TEXT NOT NULL DEFAULT ''
);
-- One rule per domain: a domain that is both allowed and denied is refused
-- here rather than by a check some caller could skip.
CREATE TABLE IF NOT EXISTS blacklist_rules (
  id     INTEGER PRIMARY KEY,
  kind   TEXT NOT NULL,
  domain TEXT NOT NULL UNIQUE
);
```

- [ ] **Step 4: Add the models**

Append to `internal/store/model.go`:

```go
// BlacklistSettings is the global filtering policy. Filtering is on by
// default; the toggle disables new blocks without deleting anything.
type BlacklistSettings struct {
	Enabled  bool
	BlockTTL int // seconds a client should cache a block
}

// BlacklistList is one source. Snapshot is the last known-good normalized
// body, and is loaded only where it is needed.
type BlacklistList struct {
	ID              int64
	Name            string
	URL             string
	Format          string
	Description     string
	Enabled         bool
	Builtin         bool
	IntervalSeconds int64
	LastAttemptAt   int64
	LastOKAt        int64
	LastError       string
	ETag            string
	LastModified    string
	EntryCount      int
	SkippedCount    int
	Snapshot        []string
}

// BlacklistRule is one one-off rule. Kind is "allow" or "deny".
type BlacklistRule struct {
	ID     int64
	Kind   string
	Domain string
}
```

- [ ] **Step 5: Write `internal/store/blacklist.go`**

```go
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

func (s *Store) BlacklistSettings() (BlacklistSettings, error) {
	var b BlacklistSettings
	err := s.db.QueryRow(`SELECT enabled, block_ttl FROM blacklist_settings WHERE id = 1`).
		Scan(&b.Enabled, &b.BlockTTL)
	if errors.Is(err, sql.ErrNoRows) {
		return BlacklistSettings{Enabled: true, BlockTTL: 60}, nil
	}
	return b, err
}

func (s *Store) SetBlacklistSettings(b BlacklistSettings) error {
	_, err := s.db.Exec(`
		INSERT INTO blacklist_settings(id, enabled, block_ttl) VALUES(1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled,
		                              block_ttl = excluded.block_ttl`, b.Enabled, b.BlockTTL)
	return err
}

const listColumns = `id, name, url, format, description, enabled, builtin, interval_seconds,
	last_attempt_at, last_ok_at, last_error, etag, last_modified, entry_count, skipped_count`

// scanList reads the metadata columns. body is the snapshot text, or "" where
// the caller did not select it.
func scanList(sc interface{ Scan(...any) error }, body *string) (BlacklistList, error) {
	var l BlacklistList
	dest := []any{
		&l.ID, &l.Name, &l.URL, &l.Format, &l.Description, &l.Enabled, &l.Builtin,
		&l.IntervalSeconds, &l.LastAttemptAt, &l.LastOKAt, &l.LastError,
		&l.ETag, &l.LastModified, &l.EntryCount, &l.SkippedCount,
	}
	if body != nil {
		dest = append(dest, body)
	}
	if err := sc.Scan(dest...); err != nil {
		return BlacklistList{}, err
	}
	if body != nil && *body != "" {
		l.Snapshot = strings.Split(*body, "\n")
	}
	return l, nil
}

// BlacklistLists loads every list with its snapshot. The policy rebuild is the
// caller; the UI uses BlacklistListMetas instead.
func (s *Store) BlacklistLists() ([]BlacklistList, error) {
	return s.blacklistLists(true)
}

// BlacklistListMetas loads every list without its snapshot, so rendering a
// screen does not pull megabytes of domains out of the database.
func (s *Store) BlacklistListMetas() ([]BlacklistList, error) {
	return s.blacklistLists(false)
}

func (s *Store) blacklistLists(withBody bool) ([]BlacklistList, error) {
	q := `SELECT ` + listColumns
	if withBody {
		q += `, snapshot`
	}
	q += ` FROM blacklist_lists ORDER BY builtin DESC, name`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BlacklistList{}
	for rows.Next() {
		var body string
		var p *string
		if withBody {
			p = &body
		}
		l, err := scanList(rows, p)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) BlacklistListByID(id int64) (BlacklistList, error) {
	var body string
	l, err := scanList(s.db.QueryRow(`SELECT `+listColumns+`, snapshot FROM blacklist_lists WHERE id = ?`, id), &body)
	if errors.Is(err, sql.ErrNoRows) {
		return BlacklistList{}, fmt.Errorf("%w: blacklist list %d", ErrNotFound, id)
	}
	return l, err
}

// PutBlacklistList writes a list definition. It deliberately never touches the
// snapshot or the refresh metadata: editing a name must not throw away a
// working download.
func (s *Store) PutBlacklistList(l BlacklistList) (int64, error) {
	if l.ID == 0 {
		res, err := s.db.Exec(`
			INSERT INTO blacklist_lists(name, url, format, description, enabled, builtin, interval_seconds)
			VALUES(?, ?, ?, ?, ?, ?, ?)`,
			l.Name, l.URL, l.Format, l.Description, l.Enabled, l.Builtin, l.IntervalSeconds)
		if err != nil {
			if isUnique(err, "blacklist_lists.name") {
				return 0, fmt.Errorf("%w: list %s", ErrDuplicateName, l.Name)
			}
			return 0, err
		}
		return res.LastInsertId()
	}
	res, err := s.db.Exec(`
		UPDATE blacklist_lists
		SET name = ?, url = ?, format = ?, description = ?, enabled = ?, interval_seconds = ?
		WHERE id = ?`,
		l.Name, l.URL, l.Format, l.Description, l.Enabled, l.IntervalSeconds, l.ID)
	if err != nil {
		if isUnique(err, "blacklist_lists.name") {
			return 0, fmt.Errorf("%w: list %s", ErrDuplicateName, l.Name)
		}
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, fmt.Errorf("%w: blacklist list %d", ErrNotFound, l.ID)
	}
	return l.ID, nil
}

// SetBlacklistSnapshot replaces a list's body in one statement, which is what
// makes a refresh transactional: readers see the old body or the new one.
func (s *Store) SetBlacklistSnapshot(id int64, domains []string, skipped int, etag, lastModified string, at int64) error {
	res, err := s.db.Exec(`
		UPDATE blacklist_lists
		SET snapshot = ?, entry_count = ?, skipped_count = ?, etag = ?, last_modified = ?,
		    last_ok_at = ?, last_attempt_at = ?, last_error = ''
		WHERE id = ?`,
		strings.Join(domains, "\n"), len(domains), skipped, etag, lastModified, at, at, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: blacklist list %d", ErrNotFound, id)
	}
	return nil
}

// SetBlacklistError records a failed refresh. The snapshot is untouched, so
// the last known-good data keeps serving.
func (s *Store) SetBlacklistError(id int64, msg string, at int64) error {
	_, err := s.db.Exec(
		`UPDATE blacklist_lists SET last_error = ?, last_attempt_at = ? WHERE id = ?`, msg, at, id)
	return err
}

// TouchBlacklistAttempt records a refresh that succeeded with no new content,
// so a 304 does not look like a list that has stopped updating.
func (s *Store) TouchBlacklistAttempt(id, at int64) error {
	_, err := s.db.Exec(
		`UPDATE blacklist_lists SET last_attempt_at = ?, last_ok_at = ?, last_error = '' WHERE id = ?`, at, at, id)
	return err
}

func (s *Store) DeleteBlacklistList(id int64) error {
	res, err := s.db.Exec(`DELETE FROM blacklist_lists WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: blacklist list %d", ErrNotFound, id)
	}
	return nil
}

func (s *Store) BlacklistRules() ([]BlacklistRule, error) {
	rows, err := s.db.Query(`SELECT id, kind, domain FROM blacklist_rules ORDER BY kind, domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BlacklistRule{}
	for rows.Next() {
		var r BlacklistRule
		if err := rows.Scan(&r.ID, &r.Kind, &r.Domain); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) PutBlacklistRule(r BlacklistRule) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO blacklist_rules(kind, domain) VALUES(?, ?)`, r.Kind, r.Domain)
	if err != nil {
		if isUnique(err, "blacklist_rules.domain") {
			return 0, fmt.Errorf("%w: a rule for %s already exists", ErrDuplicateName, r.Domain)
		}
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) DeleteBlacklistRule(id int64) error {
	res, err := s.db.Exec(`DELETE FROM blacklist_rules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: blacklist rule %d", ErrNotFound, id)
	}
	return nil
}

// ReplaceBlacklist writes a whole imported policy in one transaction. A list
// whose URL survives the import keeps its downloaded body, so restoring a
// backup does not force every source to re-download.
func (s *Store) ReplaceBlacklist(set BlacklistSettings, lists []BlacklistList, rules []BlacklistRule) error {
	type body struct {
		snapshot                 string
		etag, lastModified       string
		entryCount, skippedCount int
		lastOKAt, lastAttemptAt  int64
	}
	kept := map[string]body{}
	rows, err := s.db.Query(`SELECT url, snapshot, etag, last_modified, entry_count, skipped_count, last_ok_at, last_attempt_at FROM blacklist_lists`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var url string
		var b body
		if err := rows.Scan(&url, &b.snapshot, &b.etag, &b.lastModified,
			&b.entryCount, &b.skippedCount, &b.lastOKAt, &b.lastAttemptAt); err != nil {
			rows.Close()
			return err
		}
		kept[url] = b
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{`DELETE FROM blacklist_rules`, `DELETE FROM blacklist_lists`} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`
		INSERT INTO blacklist_settings(id, enabled, block_ttl) VALUES(1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled,
		                              block_ttl = excluded.block_ttl`, set.Enabled, set.BlockTTL); err != nil {
		return err
	}
	for _, l := range lists {
		b := kept[l.URL]
		if _, err := tx.Exec(`
			INSERT INTO blacklist_lists(name, url, format, description, enabled, builtin, interval_seconds,
			  snapshot, etag, last_modified, entry_count, skipped_count, last_ok_at, last_attempt_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			l.Name, l.URL, l.Format, l.Description, l.Enabled, l.Builtin, l.IntervalSeconds,
			b.snapshot, b.etag, b.lastModified, b.entryCount, b.skippedCount,
			b.lastOKAt, b.lastAttemptAt); err != nil {
			if isUnique(err, "blacklist_lists.name") {
				return fmt.Errorf("%w: list %s", ErrDuplicateName, l.Name)
			}
			return err
		}
	}
	for _, r := range rules {
		if _, err := tx.Exec(`INSERT INTO blacklist_rules(kind, domain) VALUES(?, ?)`, r.Kind, r.Domain); err != nil {
			if isUnique(err, "blacklist_rules.domain") {
				return fmt.Errorf("%w: a rule for %s already exists", ErrDuplicateName, r.Domain)
			}
			return err
		}
	}
	return tx.Commit()
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/store/... -v -run Blacklist`
Expected: PASS. Then `go test ./internal/store/...` — the existing migration tests must still pass.

- [ ] **Step 7: Commit**

```bash
git add internal/store/
git commit -m "feat(store): blacklist settings, lists and one-off rules"
```

---

## Task 4: The decision snapshot and its holder

**Files:**
- Create: `internal/policy/snapshot.go`
- Create: `internal/policy/holder.go`
- Create: `internal/policy/snapshot_test.go`
- Create: `internal/policy/holder_test.go`

**Interfaces:**
- Consumes: `policy.Normalize`, `policy.NewSet` (Task 1); `store.BlacklistSettings`, `store.BlacklistList`, `store.BlacklistRule` (Task 3).
- Produces:
  - `policy.Decision{Blocked bool; Policy string; TTL uint32}`
  - `policy.PolicyForwarded = "forwarded"`, `policy.PolicyAllow = "allow"`, `policy.PolicyDeny = "deny"`
  - `policy.Build(set store.BlacklistSettings, lists []store.BlacklistList, rules []store.BlacklistRule) *Snapshot`
  - `(*policy.Snapshot).Decide(name string) Decision` — `name` may be any form; it normalizes internally
  - `policy.Source func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error)`
  - `policy.NewHolder(src Source) *Holder`
  - `(*policy.Holder).Rebuild() error`, `.Current() *Snapshot`
  - `(*policy.Holder).Decide(name string) (blocked bool, decision string, ttl uint32)` — counts as it decides
  - `(*policy.Holder).Counters() (total uint64, byList map[string]uint64)`

- [ ] **Step 1: Write the failing snapshot test**

Create `internal/policy/snapshot_test.go`:

```go
package policy

import (
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func testSnapshot(t *testing.T, enabled bool) *Snapshot {
	t.Helper()
	return Build(
		store.BlacklistSettings{Enabled: enabled, BlockTTL: 60},
		[]store.BlacklistList{
			{Name: "steven-black", Enabled: true, Snapshot: []string{"ads.example", "shared.example"}},
			{Name: "off-list", Enabled: false, Snapshot: []string{"quiet.example"}},
		},
		[]store.BlacklistRule{
			{Kind: "deny", Domain: "banned.example"},
			{Kind: "allow", Domain: "shared.example"},
			{Kind: "deny", Domain: "evil.shared.example"},
		},
	)
}

func TestDecideBlocksAListedName(t *testing.T) {
	got := testSnapshot(t, true).Decide("ads.example")
	if !got.Blocked || got.Policy != "steven-black" || got.TTL != 60 {
		t.Errorf("Decide(ads.example) = %+v, want blocked by steven-black at 60s", got)
	}
}

func TestDecideBlocksASubdomainOfAListedName(t *testing.T) {
	if got := testSnapshot(t, true).Decide("cdn.ads.example."); !got.Blocked {
		t.Errorf("Decide(cdn.ads.example.) = %+v, want blocked", got)
	}
}

func TestDecideDoesNotBlockAcrossALabelBoundary(t *testing.T) {
	if got := testSnapshot(t, true).Decide("badads.example"); got.Blocked {
		t.Errorf("Decide(badads.example) = %+v, want forwarded", got)
	}
}

// An allow rule beats the list that would otherwise block the name.
func TestAllowRuleBeatsAList(t *testing.T) {
	got := testSnapshot(t, true).Decide("shared.example")
	if got.Blocked || got.Policy != PolicyAllow {
		t.Errorf("Decide(shared.example) = %+v, want an allow decision", got)
	}
}

// An explicit deny beats an explicit allow, even the parent allow above it.
func TestDenyRuleBeatsAnAllowRule(t *testing.T) {
	got := testSnapshot(t, true).Decide("evil.shared.example")
	if !got.Blocked || got.Policy != PolicyDeny {
		t.Errorf("Decide(evil.shared.example) = %+v, want a deny decision", got)
	}
}

func TestDenyRuleBlocksSubdomains(t *testing.T) {
	if got := testSnapshot(t, true).Decide("a.banned.example"); !got.Blocked {
		t.Errorf("Decide(a.banned.example) = %+v, want blocked", got)
	}
}

func TestDisabledListDoesNotBlock(t *testing.T) {
	if got := testSnapshot(t, true).Decide("quiet.example"); got.Blocked {
		t.Errorf("Decide(quiet.example) = %+v, want forwarded: its list is disabled", got)
	}
}

// The global toggle stops new blocks without deleting anything.
func TestDisabledPolicyBlocksNothing(t *testing.T) {
	s := testSnapshot(t, false)
	for _, n := range []string{"ads.example", "banned.example"} {
		if got := s.Decide(n); got.Blocked || got.Policy != PolicyForwarded {
			t.Errorf("Decide(%q) with filtering off = %+v, want forwarded", n, got)
		}
	}
}

func TestUnmatchedNameIsForwarded(t *testing.T) {
	got := testSnapshot(t, true).Decide("example.org")
	if got.Blocked || got.Policy != PolicyForwarded {
		t.Errorf("Decide(example.org) = %+v, want forwarded", got)
	}
}

// A name that cannot be normalized is forwarded, never blocked. Filtering must
// never be the reason a strange but legal query fails.
func TestUnnormalizableNameIsForwarded(t *testing.T) {
	if got := testSnapshot(t, true).Decide("!!!"); got.Blocked {
		t.Errorf("Decide(!!!) = %+v, want forwarded", got)
	}
}

func TestBlockTTLComesFromSettings(t *testing.T) {
	s := Build(
		store.BlacklistSettings{Enabled: true, BlockTTL: 15},
		[]store.BlacklistList{{Name: "l", Enabled: true, Snapshot: []string{"ads.example"}}},
		nil)
	if got := s.Decide("ads.example"); got.TTL != 15 {
		t.Errorf("TTL = %d, want 15", got.TTL)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/policy/ -run TestDecide`
Expected: FAIL with "undefined: Build".

- [ ] **Step 3: Write `internal/policy/snapshot.go`**

```go
package policy

import "github.com/yoshiofthewire/kydns-server/internal/store"

// The values the query log's policy field can take, alongside a list name.
const (
	PolicyForwarded = "forwarded"
	PolicyAllow     = "allow"
	PolicyDeny      = "deny"
)

// defaultBlockTTL is how long a client should cache a block when settings
// carry no value.
const defaultBlockTTL = 60

// Decision is what the policy says about one forwarded name. Policy is the
// query log's policy field: "deny", "allow", a list name, or "forwarded".
type Decision struct {
	Blocked bool
	Policy  string
	TTL     uint32
}

type namedSet struct {
	name string
	set  *Set
}

// Snapshot is an immutable policy. The DNS hot path reads one with no lock;
// every change builds a new one.
type Snapshot struct {
	enabled bool
	ttl     uint32
	deny    *Set
	allow   *Set
	lists   []namedSet
}

// Build assembles a snapshot. Disabled lists are left out entirely rather than
// carried and skipped, so a disabled list costs nothing on the hot path.
func Build(set store.BlacklistSettings, lists []store.BlacklistList, rules []store.BlacklistRule) *Snapshot {
	ttl := set.BlockTTL
	if ttl <= 0 {
		ttl = defaultBlockTTL
	}
	s := &Snapshot{enabled: set.Enabled, ttl: uint32(ttl)}
	var deny, allow []string
	for _, r := range rules {
		switch r.Kind {
		case PolicyDeny:
			deny = append(deny, r.Domain)
		case PolicyAllow:
			allow = append(allow, r.Domain)
		}
	}
	s.deny, s.allow = NewSet(deny), NewSet(allow)
	for _, l := range lists {
		if !l.Enabled || len(l.Snapshot) == 0 {
			continue
		}
		s.lists = append(s.lists, namedSet{name: l.Name, set: NewSet(l.Snapshot)})
	}
	return s
}

// Decide applies the precedence the spec fixes: an explicit deny, then an
// explicit allow, then the enabled lists. A name it cannot normalize is
// forwarded: filtering never turns a strange query into a failure.
func (s *Snapshot) Decide(name string) Decision {
	if s == nil || !s.enabled {
		return Decision{Policy: PolicyForwarded}
	}
	n, err := Normalize(name)
	if err != nil {
		return Decision{Policy: PolicyForwarded}
	}
	if s.deny.Match(n) {
		return Decision{Blocked: true, Policy: PolicyDeny, TTL: s.ttl}
	}
	if s.allow.Match(n) {
		return Decision{Policy: PolicyAllow}
	}
	for _, l := range s.lists {
		if l.set.Match(n) {
			return Decision{Blocked: true, Policy: l.name, TTL: s.ttl}
		}
	}
	return Decision{Policy: PolicyForwarded}
}
```

- [ ] **Step 4: Write the failing holder test**

Create `internal/policy/holder_test.go`:

```go
package policy

import (
	"errors"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func testHolder(t *testing.T, src Source) *Holder {
	t.Helper()
	h := NewHolder(src)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHolderDecidesAndCounts(t *testing.T) {
	h := testHolder(t, func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		return store.BlacklistSettings{Enabled: true, BlockTTL: 60},
			[]store.BlacklistList{{Name: "l1", Enabled: true, Snapshot: []string{"ads.example"}}},
			nil, nil
	})
	for i := 0; i < 3; i++ {
		blocked, decision, ttl := h.Decide("ads.example.")
		if !blocked || decision != "l1" || ttl != 60 {
			t.Fatalf("Decide() = %v %q %d, want blocked by l1 at 60", blocked, decision, ttl)
		}
	}
	if blocked, _, _ := h.Decide("example.org"); blocked {
		t.Error("Decide(example.org) blocked")
	}
	total, byList := h.Counters()
	if total != 3 || byList["l1"] != 3 {
		t.Errorf("Counters() = %d %v, want 3 blocks all from l1", total, byList)
	}
}

// A failed rebuild keeps the previous snapshot serving, exactly like the zone
// holder: a transient store error must not silently disable filtering.
func TestFailedRebuildKeepsThePreviousSnapshot(t *testing.T) {
	fail := false
	h := testHolder(t, func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		if fail {
			return store.BlacklistSettings{}, nil, nil, errors.New("store is down")
		}
		return store.BlacklistSettings{Enabled: true, BlockTTL: 60},
			[]store.BlacklistList{{Name: "l1", Enabled: true, Snapshot: []string{"ads.example"}}},
			nil, nil
	})
	fail = true
	if err := h.Rebuild(); err == nil {
		t.Fatal("Rebuild() succeeded, want the store error surfaced")
	}
	if blocked, _, _ := h.Decide("ads.example"); !blocked {
		t.Error("after a failed rebuild the name is no longer blocked")
	}
}

func TestHolderBeforeFirstBuildBlocksNothing(t *testing.T) {
	h := NewHolder(func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		return store.BlacklistSettings{}, nil, nil, nil
	})
	if blocked, decision, _ := h.Decide("ads.example"); blocked || decision != PolicyForwarded {
		t.Errorf("Decide() before the first build = %v %q, want forwarded", blocked, decision)
	}
}
```

- [ ] **Step 5: Write `internal/policy/holder.go`**

```go
package policy

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// Source pulls the current policy inputs. It returns an error rather than
// partial data, so a transient store failure cannot silently empty the policy.
type Source func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error)

// Holder owns the live policy snapshot. Readers on the DNS hot path call
// Decide with no lock on the snapshot itself; writers call Rebuild, which
// builds fully before swapping the pointer.
type Holder struct {
	src Source
	cur atomic.Pointer[Snapshot]

	blocked atomic.Uint64
	mu      sync.Mutex
	byList  map[string]uint64
}

// NewHolder takes no logger: Rebuild returns its error and the caller logs it,
// so there is nothing here to log.
func NewHolder(src Source) *Holder {
	return &Holder{src: src, byList: map[string]uint64{}}
}

// Rebuild pulls fresh inputs, builds a complete snapshot, and swaps it in. It
// is all-or-nothing: any error returns before the swap.
func (h *Holder) Rebuild() error {
	set, lists, rules, err := h.src()
	if err != nil {
		return err
	}
	h.cur.Store(Build(set, lists, rules))
	return nil
}

// Current returns the live snapshot, or nil before the first successful build.
func (h *Holder) Current() *Snapshot { return h.cur.Load() }

// Decide implements dnsserver.PolicyDecider and records the block counters.
// Counting only ever happens on a block, so the common forwarded path takes no
// lock at all.
func (h *Holder) Decide(name string) (bool, string, uint32) {
	d := h.cur.Load().Decide(name)
	if d.Blocked {
		h.blocked.Add(1)
		h.mu.Lock()
		h.byList[d.Policy]++
		h.mu.Unlock()
	}
	return d.Blocked, d.Policy, d.TTL
}

// Counters returns blocked totals and counts by list. Client identity is never
// part of this: the counters say what was blocked, never who asked.
func (h *Holder) Counters() (uint64, map[string]uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]uint64, len(h.byList))
	for k, v := range h.byList {
		out[k] = v
	}
	return h.blocked.Load(), out
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/policy/... -v`
Expected: PASS, every test from Tasks 1, 2 and 4.

- [ ] **Step 7: Commit**

```bash
git add internal/policy/snapshot.go internal/policy/holder.go internal/policy/snapshot_test.go internal/policy/holder_test.go
git commit -m "feat(policy): decision snapshot with fixed precedence and an atomic holder"
```

---

## Task 5: Block forwarded names in the DNS pipeline

**Files:**
- Modify: `internal/dnsserver/server.go:16-24` — `Options`
- Modify: `internal/dnsserver/server.go:41-116` — `ServeDNS`
- Modify: `internal/dnsserver/server.go:154-173` — `logQuery`
- Create: `internal/dnsserver/policy_test.go`

**Interfaces:**
- Consumes: `(*policy.Holder).Decide` (Task 4) satisfies the new interface. `dnsserver` does **not** import `policy`.
- Produces:
  - `dnsserver.PolicyDecider` interface: `Decide(name string) (blocked bool, decision string, ttl uint32)`
  - `dnsserver.Options.Policy PolicyDecider` — nil means no filtering
  - The query log gains a `policy` field with values `local`, `allow`, `deny`, a list name, or `forwarded`

- [ ] **Step 1: Write the failing test**

Create `internal/dnsserver/policy_test.go`:

```go
package dnsserver

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)

// stubPolicy blocks exactly the names it is given.
type stubPolicy struct {
	blocked map[string]string
	calls   int
}

func (s *stubPolicy) Decide(name string) (bool, string, uint32) {
	s.calls++
	if list, ok := s.blocked[dns.Fqdn(name)]; ok {
		return true, list, 60
	}
	return false, "forwarded", 0
}

// newPolicyServer wires a server with one local service and a stub policy, and
// returns the address, the upstream (to count leaks) and the policy.
func newPolicyServer(t *testing.T, blocked map[string]string) (string, *fakeUpstream, *stubPolicy) {
	t.Helper()
	h := zone.NewHolder(func() (zone.Input, error) {
		return zone.Input{
			Zone: "home.arpa.",
			Services: []store.Service{{
				ID: 1, Name: "kypost",
				Addresses: []store.Address{{Address: "192.168.1.20"}},
			}},
		}, nil
	}, nil)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	up := okUpstream("tls://1.1.1.1:853", true)
	pol := &stubPolicy{blocked: blocked}
	addr := startUDP(t, New(Options{
		Holder:    h,
		ACL:       NewACL([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}),
		Auth:      &Authoritative{Zone: "home.arpa.", TTL: 60},
		Forwarder: newForwarder(up),
		Policy:    pol,
	}))
	return addr, up, pol
}

func TestBlockedNameReturnsLocalNXDOMAIN(t *testing.T) {
	addr, up, _ := newPolicyServer(t, map[string]string{"ads.example.": "steven-black"})
	m := queryFrom(t, addr, "127.0.0.1", "ads.example.", dns.TypeA)
	if m.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
	}
	if m.Authoritative {
		t.Error("the AA bit is set on a blocked answer, want it clear")
	}
	if len(m.Answer) != 0 {
		t.Errorf("answer = %v, want empty", m.Answer)
	}
	// The whole point: the query never left the building.
	if n := up.calls.Load(); n != 0 {
		t.Errorf("upstream saw %d queries for a blocked name, want 0", n)
	}
}

func TestBlockedAnswerCarriesTheBlockTTL(t *testing.T) {
	addr, _, _ := newPolicyServer(t, map[string]string{"ads.example.": "steven-black"})
	m := queryFrom(t, addr, "127.0.0.1", "ads.example.", dns.TypeA)
	if len(m.Ns) != 1 {
		t.Fatalf("authority = %v, want one SOA so the client caches the block", m.Ns)
	}
	soa, ok := m.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("authority = %T, want *dns.SOA", m.Ns[0])
	}
	if soa.Minttl != 60 || soa.Hdr.Ttl != 60 {
		t.Errorf("SOA ttl/minttl = %d/%d, want 60/60", soa.Hdr.Ttl, soa.Minttl)
	}
}

func TestUnblockedNameStillForwards(t *testing.T) {
	addr, up, _ := newPolicyServer(t, nil)
	m := queryFrom(t, addr, "127.0.0.1", "example.org.", dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) == 0 {
		t.Errorf("= %s with %d answers, want a forwarded answer", dns.RcodeToString[m.Rcode], len(m.Answer))
	}
	if n := up.calls.Load(); n != 1 {
		t.Errorf("upstream saw %d queries, want 1", n)
	}
}

// A local service is answered authoritatively and the policy is never
// consulted, so a public list can never blackhole it.
func TestLocalServiceIsNeverOfferedToThePolicy(t *testing.T) {
	addr, _, pol := newPolicyServer(t, map[string]string{"kypost.home.arpa.": "steven-black"})
	m := queryFrom(t, addr, "127.0.0.1", "kypost.home.arpa.", dns.TypeA)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("= %s with %d answers, want the local address", dns.RcodeToString[m.Rcode], len(m.Answer))
	}
	if !m.Authoritative {
		t.Error("the AA bit is clear on a local answer")
	}
	if pol.calls != 0 {
		t.Errorf("the policy was consulted %d times for a local name, want 0", pol.calls)
	}
}

func TestNilPolicyForwardsEverything(t *testing.T) {
	h := zone.NewHolder(func() (zone.Input, error) {
		return zone.Input{Zone: "home.arpa."}, nil
	}, nil)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	up := okUpstream("tls://1.1.1.1:853", true)
	addr := startUDP(t, New(Options{
		Holder:    h,
		ACL:       NewACL([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}),
		Auth:      &Authoritative{Zone: "home.arpa.", TTL: 60},
		Forwarder: newForwarder(up),
	}))
	if m := queryFrom(t, addr, "127.0.0.1", "example.org.", dns.TypeA); m.Rcode != dns.RcodeSuccess {
		t.Errorf("= %s, want success with no policy wired", dns.RcodeToString[m.Rcode])
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/dnsserver/ -run Policy`
Expected: FAIL — `unknown field Policy in struct literal`.

- [ ] **Step 3: Add the interface and the option**

In `internal/dnsserver/server.go`, above `type Options struct`:

```go
// PolicyDecider is the blacklist policy's slice of the DNS pipeline. Keeping
// it an interface here means dnsserver never imports the policy package, and a
// test can block a name with six lines.
//
// decision is the query log's policy field: "allow", "deny", a list name, or
// "forwarded".
type PolicyDecider interface {
	Decide(name string) (blocked bool, decision string, ttl uint32)
}
```

Add to `Options`, after `Forwarder`:

```go
	// Policy is consulted only for names the authoritative lookup declines, so
	// a public list can never blackhole a local service. Nil means no filtering.
	Policy PolicyDecider
```

- [ ] **Step 4: Thread the policy field through the reply helpers**

Replace the top of `ServeDNS` (the `reply` and `fail` closures) with:

```go
	start := time.Now()
	reply := func(m *dns.Msg, source, view, policy string) {
		// Every reply passes through here, so no path can forget the datagram
		// ceiling. Over-large answers are common now that DO=1 is forwarded.
		if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
			m.Truncate(clientUDPSize(r))
		}
		if err := w.WriteMsg(m); err != nil {
			s.o.Logger.Warn("write reply", "error", err)
		}
		s.logQuery(r, m, w, source, view, policy, time.Since(start))
	}
	fail := func(rcode int, source string) {
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		reply(m, source, "", "")
	}
```

Update the authoritative branch to pass `"local"`:

```go
	if m := s.o.Auth.Answer(snap, view, q); m != nil {
		rcode := m.Rcode
		m.SetRcode(r, rcode)
		m.Authoritative = true
		reply(m, "authoritative", view, "local")
		return
	}
```

- [ ] **Step 5: Insert the policy check between the authoritative lookup and the forwarder**

Immediately after the authoritative branch and before the `if s.o.Forwarder == nil` check:

```go
	// The name is not ours, so it would be forwarded. This is the only place
	// filtering applies, and it decides before anything leaves the machine.
	policy := ""
	if s.o.Policy != nil {
		blocked, decision, ttl := s.o.Policy.Decide(q.Name)
		policy = decision
		if blocked {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError)
			m.Authoritative = false // the block is local policy, not zone data
			m.RecursionAvailable = true
			m.Ns = []dns.RR{blockSOA(q.Name, ttl)}
			reply(m, "blocked", view, decision)
			return
		}
	}
```

Then pass `policy` to the two remaining `reply` calls in the forward path:

```go
	reply(out, "forward", view, policy)
```

and change the forward-failure path's `fail(dns.RcodeServerFailure, "forward")` — leave it as is; `fail` supplies an empty policy.

- [ ] **Step 6: Add `blockSOA`**

Append to `internal/dnsserver/server.go`:

```go
// blockSOA synthesizes the authority record that lets a client cache a block.
// Its owner is the queried name, so the negative answer is cached for exactly
// that name and nothing wider.
func blockSOA(qname string, ttl uint32) *dns.SOA {
	n := dns.Fqdn(qname)
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: n, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      n,
		Mbox:    n,
		Serial:  1,
		Refresh: 3600, Retry: 600, Expire: 604800, Minttl: ttl,
	}
}
```

- [ ] **Step 7: Add the `policy` field to the query log**

Replace `logQuery`:

```go
// logQuery honors the two-flag policy: query logging is off by default, and
// the client IP needs its own separate flag. The policy field says which
// decision produced the answer; it never says who asked.
func (s *Server) logQuery(r, m *dns.Msg, w dns.ResponseWriter, source, view, policy string, d time.Duration) {
	if !s.o.LogQueries || len(r.Question) == 0 {
		return
	}
	q := r.Question[0]
	args := []any{
		"qname", q.Name,
		"qtype", dns.TypeToString[q.Qtype],
		"rcode", dns.RcodeToString[m.Rcode],
		"source", source,
		"view", view,
		"policy", policy,
		"duration_ms", d.Milliseconds(),
	}
	if s.o.LogClientIP {
		args = append(args, "client", w.RemoteAddr().String())
	}
	s.o.Logger.Info("query", args...)
}
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `go test ./internal/dnsserver/... -v`
Expected: PASS, including every pre-existing server test.

- [ ] **Step 9: Verify the whole tree**

Run: `go build ./... && go vet ./... && gofmt -l . && CGO_ENABLED=0 go test ./...`
Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add internal/dnsserver/
git commit -m "feat(dns): block forwarded names locally, never upstream"
```

---

## Task 6: The bounded HTTPS fetcher

**Files:**
- Create: `internal/policy/fetch.go`
- Create: `internal/policy/fetch_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `policy.MaxListBytes` — `int64` ceiling, `32 << 20`
  - `policy.NewFetcher(timeout time.Duration) *Fetcher`
  - `policy.FetchResult{Body []byte; ETag, LastModified string; NotModified bool}`
  - `(*policy.Fetcher).Fetch(ctx context.Context, rawURL, etag, lastModified string) (FetchResult, error)`
  - `(*policy.Fetcher).Client *http.Client` — exported so a test can point it at an `httptest.NewTLSServer`

- [ ] **Step 1: Write the failing test**

Create `internal/policy/fetch_test.go`:

```go
package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestFetcher(t *testing.T, srv *httptest.Server) *Fetcher {
	t.Helper()
	f := NewFetcher(5 * time.Second)
	// The test server uses a self-signed certificate; reuse its client so
	// verification stays on in production code and on in the test.
	f.Client.Transport = srv.Client().Transport
	return f
}

func TestFetchReturnsBodyAndValidators(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `W/"v1"`)
		w.Header().Set("Last-Modified", "Mon, 01 Jan 2026 00:00:00 GMT")
		w.Write([]byte("ads.example\n"))
	}))
	defer srv.Close()

	got, err := newTestFetcher(t, srv).Fetch(context.Background(), srv.URL, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Body) != "ads.example\n" {
		t.Errorf("Body = %q", got.Body)
	}
	if got.ETag != `W/"v1"` || got.LastModified == "" {
		t.Errorf("validators = %q / %q, want both captured", got.ETag, got.LastModified)
	}
	if got.NotModified {
		t.Error("NotModified = true on a 200")
	}
}

func TestFetchSendsValidatorsAndHandles304(t *testing.T) {
	var gotETag, gotSince, gotUA, gotCookie string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotETag = r.Header.Get("If-None-Match")
		gotSince = r.Header.Get("If-Modified-Since")
		gotUA = r.Header.Get("User-Agent")
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	got, err := newTestFetcher(t, srv).Fetch(context.Background(), srv.URL, `W/"v1"`, "Mon, 01 Jan 2026 00:00:00 GMT")
	if err != nil {
		t.Fatal(err)
	}
	if !got.NotModified || got.Body != nil {
		t.Errorf("= %+v, want NotModified with no body", got)
	}
	if gotETag != `W/"v1"` || gotSince == "" {
		t.Errorf("sent validators %q / %q, want both", gotETag, gotSince)
	}
	// Nothing that identifies this installation or its users may go out.
	if gotUA != "kydns" {
		t.Errorf("User-Agent = %q, want the fixed %q", gotUA, "kydns")
	}
	if gotCookie != "" {
		t.Errorf("Cookie = %q, want none", gotCookie)
	}
}

func TestFetchRefusesPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ads.example\n"))
	}))
	defer srv.Close()
	if _, err := NewFetcher(time.Second).Fetch(context.Background(), srv.URL, "", ""); err == nil {
		t.Error("Fetch() accepted an http:// URL")
	}
}

func TestFetchRefusesARedirectOffHTTPS(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ads.example\n"))
	}))
	defer plain.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer srv.Close()
	if _, err := newTestFetcher(t, srv).Fetch(context.Background(), srv.URL, "", ""); err == nil {
		t.Error("Fetch() followed a redirect to plain HTTP")
	}
}

func TestFetchRefusesAnEndlessRedirectChain(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/again", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := newTestFetcher(t, srv).Fetch(context.Background(), srv.URL, "", ""); err == nil {
		t.Error("Fetch() followed redirects without limit")
	}
}

func TestFetchRefusesAnOversizedBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 200; i++ {
			w.Write([]byte(strings.Repeat("x", 1024)))
		}
	}))
	defer srv.Close()
	f := newTestFetcher(t, srv)
	f.MaxBytes = 4096
	if _, err := f.Fetch(context.Background(), srv.URL, "", ""); err == nil {
		t.Error("Fetch() accepted a body past the ceiling")
	}
}

func TestFetchReportsAnErrorStatus(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := newTestFetcher(t, srv).Fetch(context.Background(), srv.URL, "", ""); err == nil {
		t.Error("Fetch() accepted a 404")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/policy/ -run TestFetch`
Expected: FAIL with "undefined: NewFetcher".

- [ ] **Step 3: Write `internal/policy/fetch.go`**

```go
package policy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// MaxListBytes bounds one download. The largest maintained hosts file is a few
// megabytes; this leaves room without letting a hostile source exhaust memory.
const MaxListBytes int64 = 32 << 20

// maxRedirects bounds a redirect chain.
const maxRedirects = 5

// userAgent is fixed and says nothing about this installation or its users.
const userAgent = "kydns"

// FetchResult is one download. NotModified means the server answered 304 and
// the caller should keep its current snapshot.
type FetchResult struct {
	Body         []byte
	ETag         string
	LastModified string
	NotModified  bool
}

// Fetcher downloads list bodies. Client is exported so a test can swap its
// transport; production code never touches it.
type Fetcher struct {
	Client   *http.Client
	MaxBytes int64
}

func NewFetcher(timeout time.Duration) *Fetcher {
	return &Fetcher{
		MaxBytes: MaxListBytes,
		Client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return fmt.Errorf("stopped after %d redirects", maxRedirects)
				}
				// A redirect off HTTPS would silently drop verification.
				if req.URL.Scheme != "https" {
					return fmt.Errorf("redirect to a non-https URL (%s)", req.URL.Scheme)
				}
				return nil
			},
		},
	}
}

// Fetch downloads rawURL over verified HTTPS. It sends the cache validators it
// is given and nothing else: no query names, no client addresses, no cookies.
func (f *Fetcher) Fetch(ctx context.Context, rawURL, etag, lastModified string) (FetchResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return FetchResult{}, err
	}
	if u.Scheme != "https" {
		return FetchResult{}, errors.New("a list URL must be https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return FetchResult{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/plain")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}

	resp, err := f.Client.Do(req)
	if err != nil {
		return FetchResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return FetchResult{NotModified: true}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return FetchResult{}, fmt.Errorf("status %s", resp.Status)
	}

	// Read one byte past the ceiling so an oversized body is an error rather
	// than a silently truncated list.
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.MaxBytes+1))
	if err != nil {
		return FetchResult{}, err
	}
	if int64(len(body)) > f.MaxBytes {
		return FetchResult{}, fmt.Errorf("list exceeds %d bytes", f.MaxBytes)
	}
	return FetchResult{
		Body:         body,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/policy/ -run TestFetch -v`
Expected: PASS, all seven tests.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/fetch.go internal/policy/fetch_test.go
git commit -m "feat(policy): bounded verified-HTTPS list fetcher"
```

---

## Task 7: Built-in manifest and the refresh scheduler

**Files:**
- Create: `internal/policy/builtin.json`
- Create: `internal/policy/manifest.go`
- Create: `internal/policy/refresher.go`
- Create: `internal/policy/manifest_test.go`
- Create: `internal/policy/refresher_test.go`

**Interfaces:**
- Consumes: `policy.Parse`, `policy.ParseResult` (Task 2); `store` blacklist methods (Task 3); `(*policy.Holder).Rebuild` (Task 4); `(*policy.Fetcher).Fetch` (Task 6).
- Produces:
  - `policy.Builtin{Name, Description, URL, Format, License, Attribution string; IntervalSeconds int64}`
  - `policy.Manifest{Version int; Lists []Builtin}`
  - `policy.BuiltinManifest() (Manifest, error)`
  - `policy.SeedBuiltins(st *store.Store) error`
  - `policy.RefreshCadence` — `90 * time.Second`
  - `policy.NewRefresher(st *store.Store, f *Fetcher, h *Holder, logger *slog.Logger) *Refresher`
  - `(*policy.Refresher).Run(ctx context.Context)`
  - `(*policy.Refresher).RefreshDue(ctx context.Context)` — honors each list's interval
  - `(*policy.Refresher).RefreshList(ctx context.Context, id int64) error` — ignores the interval
  - `(*policy.Refresher).RefreshAll(ctx context.Context) error` — ignores every interval
  - `(*policy.Refresher).Now func() time.Time` — swappable for tests

- [ ] **Step 1: Create the manifest**

Create `internal/policy/builtin.json`:

```json
{
  "version": 1,
  "lists": [
    {
      "name": "steven-black",
      "description": "Unified hosts file: adware and malware domains, consolidated from several maintained sources.",
      "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
      "format": "hosts",
      "license": "MIT",
      "attribution": "StevenBlack/hosts contributors",
      "interval_seconds": 86400
    }
  ]
}
```

- [ ] **Step 2: Write the failing manifest test**

Create `internal/policy/manifest_test.go`:

```go
package policy

import (
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
	"path/filepath"
)

func TestBuiltinManifestIsUsable(t *testing.T) {
	m, err := BuiltinManifest()
	if err != nil {
		t.Fatal(err)
	}
	if m.Version < 1 || len(m.Lists) == 0 {
		t.Fatalf("manifest = %+v, want a versioned, non-empty manifest", m)
	}
	for _, l := range m.Lists {
		if l.Name == "" || l.License == "" || l.Attribution == "" || l.Description == "" {
			t.Errorf("built-in %+v is missing name, description, license or attribution", l)
		}
		if !strings.HasPrefix(l.URL, "https://") {
			t.Errorf("built-in %s uses %q, want an https URL", l.Name, l.URL)
		}
		if !ValidFormat(l.Format) {
			t.Errorf("built-in %s declares format %q", l.Name, l.Format)
		}
		if l.IntervalSeconds <= 0 {
			t.Errorf("built-in %s has interval %d", l.Name, l.IntervalSeconds)
		}
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSeedBuiltinsIsIdempotentAndRespectsOperatorEdits(t *testing.T) {
	st := openStore(t)
	if err := SeedBuiltins(st); err != nil {
		t.Fatal(err)
	}
	lists, err := st.BlacklistListMetas()
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) == 0 {
		t.Fatal("SeedBuiltins() added nothing")
	}
	// Built-ins are on by default.
	if !lists[0].Enabled || !lists[0].Builtin {
		t.Errorf("seeded list = %+v, want enabled and marked built-in", lists[0])
	}

	// An operator turns one off; re-seeding must not turn it back on.
	off := lists[0]
	off.Enabled = false
	if _, err := st.PutBlacklistList(off); err != nil {
		t.Fatal(err)
	}
	if err := SeedBuiltins(st); err != nil {
		t.Fatal(err)
	}
	after, err := st.BlacklistListMetas()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(lists) {
		t.Errorf("re-seeding produced %d lists, want %d", len(after), len(lists))
	}
	if after[0].Enabled {
		t.Error("re-seeding re-enabled a list the operator turned off")
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `go test ./internal/policy/ -run Builtin`
Expected: FAIL with "undefined: BuiltinManifest".

- [ ] **Step 4: Write `internal/policy/manifest.go`**

```go
package policy

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// builtinJSON is the versioned manifest of maintained sources. A release can
// change it without touching policy code.
//
//go:embed builtin.json
var builtinJSON []byte

// Builtin is one shipped source, with the license and attribution its terms
// require and the UI displays.
type Builtin struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	URL             string `json:"url"`
	Format          string `json:"format"`
	License         string `json:"license"`
	Attribution     string `json:"attribution"`
	IntervalSeconds int64  `json:"interval_seconds"`
}

type Manifest struct {
	Version int       `json:"version"`
	Lists   []Builtin `json:"lists"`
}

// BuiltinManifest parses the embedded manifest and rejects an entry that would
// not be a legal list, so a bad release fails at startup rather than at
// refresh time.
func BuiltinManifest() (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(builtinJSON, &m); err != nil {
		return Manifest{}, fmt.Errorf("builtin manifest: %w", err)
	}
	if m.Version < 1 {
		return Manifest{}, errors.New("builtin manifest: version is required")
	}
	for _, l := range m.Lists {
		if l.Name == "" || l.License == "" || l.Attribution == "" {
			return Manifest{}, fmt.Errorf("builtin manifest: %q lacks name, license or attribution", l.Name)
		}
		if !ValidFormat(l.Format) {
			return Manifest{}, fmt.Errorf("builtin manifest: %q declares format %q", l.Name, l.Format)
		}
		if l.IntervalSeconds <= 0 {
			return Manifest{}, fmt.Errorf("builtin manifest: %q has no refresh interval", l.Name)
		}
	}
	return m, nil
}

// SeedBuiltins inserts any manifest entry the database does not already hold,
// by name. It never updates an existing row: a list the operator disabled or
// retuned stays that way across upgrades.
func SeedBuiltins(st *store.Store) error {
	m, err := BuiltinManifest()
	if err != nil {
		return err
	}
	have, err := st.BlacklistListMetas()
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(have))
	for _, l := range have {
		known[l.Name] = true
	}
	for _, b := range m.Lists {
		if known[b.Name] {
			continue
		}
		if _, err := st.PutBlacklistList(store.BlacklistList{
			Name: b.Name, URL: b.URL, Format: b.Format,
			Description:     b.Description + " (" + b.License + ", " + b.Attribution + ")",
			Enabled:         true,
			Builtin:         true,
			IntervalSeconds: b.IntervalSeconds,
		}); err != nil {
			return err
		}
	}
	return nil
}
```

- [ ] **Step 5: Write the failing refresher test**

Create `internal/policy/refresher_test.go`:

```go
package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// newRefresher wires a refresher over a real store and a test HTTPS server.
func newRefresher(t *testing.T, srv *httptest.Server) (*store.Store, *Refresher, *Holder) {
	t.Helper()
	st := openStore(t)
	h := NewHolder(func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		set, err := st.BlacklistSettings()
		if err != nil {
			return set, nil, nil, err
		}
		lists, err := st.BlacklistLists()
		if err != nil {
			return set, nil, nil, err
		}
		rules, err := st.BlacklistRules()
		return set, lists, rules, err
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	f := newTestFetcher(t, srv)
	return st, NewRefresher(st, f, h, nil), h
}

func TestRefreshStoresAParsedListAndBlocks(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# comment\nads.example\nnot a domain\n"))
	}))
	defer srv.Close()
	st, ref, h := newRefresher(t, srv)

	id, err := st.PutBlacklistList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatDomains, Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ref.RefreshList(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	got, err := st.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.EntryCount != 1 || got.SkippedCount != 1 || got.LastError != "" || got.LastOKAt == 0 {
		t.Errorf("= %+v, want 1 entry, 1 skipped, no error", got)
	}
	if blocked, decision, _ := h.Decide("ads.example"); !blocked || decision != "l1" {
		t.Errorf("Decide() = %v %q, want blocked by l1 right after the refresh", blocked, decision)
	}
}

// The property that keeps DNS working when a list host goes down.
func TestFailedRefreshKeepsTheLastGoodSnapshotServing(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Write([]byte("ads.example\n"))
	}))
	defer srv.Close()
	st, ref, h := newRefresher(t, srv)

	id, err := st.PutBlacklistList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatDomains, Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ref.RefreshList(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	fail.Store(true)
	if err := ref.RefreshList(context.Background(), id); err == nil {
		t.Fatal("RefreshList() succeeded against a failing source")
	}
	got, err := st.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastError == "" {
		t.Error("the failure was not recorded")
	}
	if len(got.Snapshot) != 1 {
		t.Errorf("Snapshot = %v, want the last good body retained", got.Snapshot)
	}
	if blocked, _, _ := h.Decide("ads.example"); !blocked {
		t.Error("a failed refresh stopped the name being blocked")
	}
}

// A malformed body is treated exactly like a failed download.
func TestUnparseableBodyKeepsTheLastGoodSnapshot(t *testing.T) {
	var junk atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if junk.Load() {
			w.Write([]byte("<html>we moved</html>\n"))
			return
		}
		w.Write([]byte("||ads.example^\n"))
	}))
	defer srv.Close()
	st, ref, h := newRefresher(t, srv)

	id, err := st.PutBlacklistList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatAdblock, Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ref.RefreshList(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	junk.Store(true)
	if err := ref.RefreshList(context.Background(), id); err == nil {
		t.Fatal("RefreshList() accepted a body that produced no usable domains")
	}
	if blocked, _, _ := h.Decide("ads.example"); !blocked {
		t.Error("a junk body dropped the working snapshot")
	}
}

func TestRefreshDueHonorsTheInterval(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ads.example\n"))
	}))
	defer srv.Close()
	st, ref, _ := newRefresher(t, srv)

	now := time.Unix(1_000_000, 0)
	ref.Now = func() time.Time { return now }
	if _, err := st.PutBlacklistList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatDomains, Enabled: true, IntervalSeconds: 3600,
	}); err != nil {
		t.Fatal(err)
	}

	ref.RefreshDue(context.Background())
	ref.RefreshDue(context.Background())
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1: the second pass is inside the interval", hits.Load())
	}
	now = now.Add(2 * time.Hour)
	ref.RefreshDue(context.Background())
	if hits.Load() != 2 {
		t.Errorf("hits = %d, want 2 once the interval elapsed", hits.Load())
	}
}

func TestRefreshDueSkipsDisabledLists(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ads.example\n"))
	}))
	defer srv.Close()
	st, ref, _ := newRefresher(t, srv)
	if _, err := st.PutBlacklistList(store.BlacklistList{
		Name: "off", URL: srv.URL, Format: FormatDomains, Enabled: false, IntervalSeconds: 60,
	}); err != nil {
		t.Fatal(err)
	}
	ref.RefreshDue(context.Background())
	if hits.Load() != 0 {
		t.Errorf("hits = %d, want 0 for a disabled list", hits.Load())
	}
}

func TestNotModifiedKeepsTheSnapshotAndClearsTheError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `W/"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `W/"v1"`)
		w.Write([]byte("ads.example\n"))
	}))
	defer srv.Close()
	st, ref, h := newRefresher(t, srv)
	id, err := st.PutBlacklistList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatDomains, Enabled: true, IntervalSeconds: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ref.RefreshList(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := ref.RefreshList(context.Background(), id); err != nil {
		t.Fatalf("second RefreshList() (a 304): %v", err)
	}
	got, err := st.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Snapshot) != 1 || got.LastError != "" {
		t.Errorf("after a 304 = %+v, want the snapshot kept and no error", got)
	}
	if blocked, _, _ := h.Decide("ads.example"); !blocked {
		t.Error("a 304 dropped the snapshot")
	}
}
```

- [ ] **Step 6: Write `internal/policy/refresher.go`**

> **Correction applied during implementation (commit 224048e).** The `refresh`
> helper below returns a single `bool` documented as "the snapshot changed",
> but all three callers treat `false` as "failed". On an HTTP 304 — a success —
> it returns false, so `RefreshList` returns a bogus error and `RefreshAll`
> records a bogus failure. `TestNotModifiedKeepsTheSnapshotAndClearsTheError`
> catches this. The shipped code splits the return into `(ok, changed bool)`:
> download/parse/zero-domain/store errors return `(false, false)`, a 304 returns
> `(true, false)`, and a successful install returns `(true, true)`. `RefreshDue`
> gates its rebuild on `changed`; `RefreshAll` and `RefreshList` gate their error
> on `ok`. The public signatures of `RefreshDue`, `RefreshAll` and `RefreshList`
> are unchanged, so nothing in Tasks 8-13 is affected. Read
> `internal/policy/refresher.go` for the authoritative version.

```go
package policy

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// RefreshCadence is the foreground scheduler tick. Each list still obeys its
// own interval, so a 90-second tick does not mean a 90-second download.
const RefreshCadence = 90 * time.Second

// Refresher downloads and installs list bodies. Now is swappable so a test can
// step past an interval without sleeping.
type Refresher struct {
	st     *store.Store
	f      *Fetcher
	h      *Holder
	logger *slog.Logger
	Now    func() time.Time
}

func NewRefresher(st *store.Store, f *Fetcher, h *Holder, logger *slog.Logger) *Refresher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Refresher{st: st, f: f, h: h, logger: logger, Now: time.Now}
}

// Run refreshes due lists on the foreground cadence, catching up immediately
// on start rather than waiting out a first tick.
func (r *Refresher) Run(ctx context.Context) {
	t := time.NewTicker(RefreshCadence)
	defer t.Stop()
	for {
		r.RefreshDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RefreshDue refreshes every enabled list whose interval has elapsed. A list
// that fails is logged and skipped: one bad source never stops the others.
func (r *Refresher) RefreshDue(ctx context.Context) {
	lists, err := r.st.BlacklistListMetas()
	if err != nil {
		r.logger.Warn("blacklist: list sources", "error", err)
		return
	}
	now := r.Now().Unix()
	changed := false
	for _, l := range lists {
		if !l.Enabled || now-l.LastAttemptAt < l.IntervalSeconds {
			continue
		}
		if r.refresh(ctx, l) {
			changed = true
		}
	}
	if changed {
		r.rebuild()
	}
}

// RefreshAll refreshes every enabled list now, ignoring intervals. This is the
// "refresh all" button.
func (r *Refresher) RefreshAll(ctx context.Context) error {
	lists, err := r.st.BlacklistListMetas()
	if err != nil {
		return err
	}
	var joined error
	for _, l := range lists {
		if !l.Enabled {
			continue
		}
		if !r.refresh(ctx, l) {
			joined = errors.Join(joined, errors.New("refresh failed: "+l.Name))
		}
	}
	r.rebuild()
	return joined
}

// RefreshList refreshes one list now, ignoring its interval.
func (r *Refresher) RefreshList(ctx context.Context, id int64) error {
	l, err := r.st.BlacklistListByID(id)
	if err != nil {
		return err
	}
	if !r.refresh(ctx, l) {
		after, lookupErr := r.st.BlacklistListByID(id)
		if lookupErr == nil && after.LastError != "" {
			return errors.New(after.LastError)
		}
		return errors.New("refresh failed")
	}
	r.rebuild()
	return nil
}

// refresh downloads, parses and installs one list. It reports whether the
// stored snapshot changed. Every failure path leaves the previous snapshot
// exactly where it was.
func (r *Refresher) refresh(ctx context.Context, l store.BlacklistList) bool {
	at := r.Now().Unix()
	res, err := r.f.Fetch(ctx, l.URL, l.ETag, l.LastModified)
	if err != nil {
		r.fail(l, err, at)
		return false
	}
	if res.NotModified {
		if err := r.st.TouchBlacklistAttempt(l.ID, at); err != nil {
			r.logger.Warn("blacklist: record refresh", "list", l.Name, "error", err)
		}
		r.logger.Info("blacklist list unchanged", "list", l.Name, "entries", l.EntryCount)
		return false
	}
	parsed, err := Parse(bytes.NewReader(res.Body), l.Format)
	if err != nil {
		r.fail(l, err, at)
		return false
	}
	// A body that yields nothing usable is a broken source, not an empty list.
	// Installing it would silently unblock everything the list covered.
	if len(parsed.Domains) == 0 {
		r.fail(l, errors.New("no usable domains in the downloaded body"), at)
		return false
	}
	if err := r.st.SetBlacklistSnapshot(l.ID, parsed.Domains, parsed.Skipped,
		res.ETag, res.LastModified, at); err != nil {
		r.fail(l, err, at)
		return false
	}
	// Counts only: never the URL's credentials, never the content.
	r.logger.Info("blacklist list refreshed",
		"list", l.Name, "entries", len(parsed.Domains), "skipped", parsed.Skipped)
	return true
}

func (r *Refresher) fail(l store.BlacklistList, cause error, at int64) {
	if err := r.st.SetBlacklistError(l.ID, cause.Error(), at); err != nil {
		r.logger.Warn("blacklist: record failure", "list", l.Name, "error", err)
	}
	r.logger.Warn("blacklist list refresh failed, still serving the previous snapshot",
		"list", l.Name, "entries", l.EntryCount, "error", cause)
}

func (r *Refresher) rebuild() {
	if err := r.h.Rebuild(); err != nil {
		r.logger.Error("blacklist: rebuild failed, still serving the previous policy", "error", err)
	}
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./internal/policy/... -v`
Expected: PASS, every test in the package.

- [ ] **Step 8: Commit**

```bash
git add internal/policy/
git commit -m "feat(policy): built-in manifest and transactional refresh scheduler"
```

---

## Task 8: The validating service layer

**Files:**
- Modify: `internal/registry/validate.go` — export the error constructor
- Create: `internal/policy/service.go`
- Create: `internal/policy/service_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1–7.
- Produces:
  - `registry.Invalid(field, code, format string, args ...any) error` — returns a `*registry.ValidationError`, so `adminapi.writeRegistryErr` maps policy failures with no new code
  - `policy.NewService(st *store.Store, h *Holder, r *Refresher) *Service`
  - `(*Service).Settings() (store.BlacklistSettings, error)`
  - `(*Service).SetSettings(enabled bool, blockTTL int) error`
  - `(*Service).Lists() ([]store.BlacklistList, error)` — metadata only
  - `(*Service).PutList(l store.BlacklistList) (int64, error)`
  - `(*Service).DeleteList(id int64) error`
  - `(*Service).Rules() ([]store.BlacklistRule, error)`
  - `(*Service).AddRule(kind, domain string) (int64, error)`
  - `(*Service).DeleteRule(id int64) error`
  - `(*Service).Refresh(ctx context.Context, id int64) error` — `id == 0` means every list
  - `(*Service).Test(name string) (Decision, error)`
  - `(*Service).Counters() (uint64, map[string]uint64)`

**Rules this task locks in:** a list URL must be `https://`; the format must be one of the three; the refresh interval floor is 300 seconds; a built-in list may be enabled, disabled and re-tuned but not deleted or re-pointed at another URL; the block TTL is 1–3600 seconds; a rule domain goes through `Normalize`; a duplicate or conflicting rule is refused by the store's unique index and surfaces as `store.ErrDuplicateName`.

- [ ] **Step 1: Export the validation-error constructor**

In `internal/registry/validate.go`, directly below `func invalid(...)`:

```go
// Invalid builds a ValidationError. Exported so sibling services report field
// failures in the form both transports already render.
func Invalid(field, code, format string, args ...any) error {
	return invalid(field, code, format, args...)
}
```

- [ ] **Step 2: Write the failing test**

Create `internal/policy/service_test.go`:

```go
package policy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func newService(t *testing.T, srv *httptest.Server) (*store.Store, *Service) {
	t.Helper()
	st, ref, h := newRefresher(t, srv)
	return st, NewService(st, h, ref)
}

func quietServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPutListRejectsBadDefinitions(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	_, svc := newService(t, srv)
	cases := map[string]store.BlacklistList{
		"no name":        {URL: "https://e/x", Format: FormatDomains},
		"no url":         {Name: "l", Format: FormatDomains},
		"plain http":     {Name: "l", URL: "http://e/x", Format: FormatDomains},
		"file url":       {Name: "l", URL: "file:///etc/passwd", Format: FormatDomains},
		"unknown format": {Name: "l", URL: "https://e/x", Format: "regex"},
		"tiny interval":  {Name: "l", URL: "https://e/x", Format: FormatDomains, IntervalSeconds: 5},
	}
	for label, l := range cases {
		if _, err := svc.PutList(l); err == nil {
			t.Errorf("PutList(%s) succeeded, want a validation error", label)
		} else {
			var ve *registry.ValidationError
			if !errors.As(err, &ve) {
				t.Errorf("PutList(%s) = %T, want a *registry.ValidationError", label, err)
			}
		}
	}
}

func TestPutListDefaultsTheInterval(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	st, svc := newService(t, srv)
	id, err := svc.PutList(store.BlacklistList{Name: "l", URL: "https://e/x", Format: FormatDomains, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.IntervalSeconds != defaultInterval {
		t.Errorf("IntervalSeconds = %d, want the %d default", got.IntervalSeconds, defaultInterval)
	}
}

// A built-in may be turned off, but never deleted or re-pointed: that is what
// makes it a shipped source rather than a suggestion.
func TestBuiltinListIsProtected(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	st, svc := newService(t, srv)
	if err := SeedBuiltins(st); err != nil {
		t.Fatal(err)
	}
	lists, err := svc.Lists()
	if err != nil {
		t.Fatal(err)
	}
	b := lists[0]
	if !b.Builtin {
		t.Fatalf("first list = %+v, want the seeded built-in", b)
	}
	if err := svc.DeleteList(b.ID); err == nil {
		t.Error("DeleteList() removed a built-in")
	}
	moved := b
	moved.URL = "https://elsewhere.example/hosts"
	if _, err := svc.PutList(moved); err == nil {
		t.Error("PutList() re-pointed a built-in at another URL")
	}
	off := b
	off.Enabled = false
	if _, err := svc.PutList(off); err != nil {
		t.Errorf("PutList() could not disable a built-in: %v", err)
	}
}

func TestAddRuleNormalizesAndValidates(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	st, svc := newService(t, srv)
	if _, err := svc.AddRule("deny", "  ADS.Example.  "); err != nil {
		t.Fatal(err)
	}
	rules, err := st.BlacklistRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Domain != "ads.example" {
		t.Errorf("rules = %+v, want the normalized domain", rules)
	}
	if _, err := svc.AddRule("maybe", "x.example"); err == nil {
		t.Error("AddRule() accepted an unknown kind")
	}
	if _, err := svc.AddRule("deny", "not a domain"); err == nil {
		t.Error("AddRule() accepted a malformed domain")
	}
}

func TestConflictingRuleIsRefused(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	_, svc := newService(t, srv)
	if _, err := svc.AddRule("deny", "ads.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddRule("allow", "ads.example"); !errors.Is(err, store.ErrDuplicateName) {
		t.Errorf("conflicting rule = %v, want ErrDuplicateName", err)
	}
}

func TestSetSettingsBoundsTheBlockTTL(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	_, svc := newService(t, srv)
	for _, ttl := range []int{0, -1, 3601} {
		if err := svc.SetSettings(true, ttl); err == nil {
			t.Errorf("SetSettings(ttl=%d) succeeded, want a validation error", ttl)
		}
	}
	if err := svc.SetSettings(false, 30); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled || got.BlockTTL != 30 {
		t.Errorf("Settings() = %+v, want {false 30}", got)
	}
}

// The toggle takes effect without a restart, and re-enabling restores the
// existing snapshots immediately.
func TestTogglingFilteringTakesEffectAtOnce(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	st, svc := newService(t, srv)
	id, err := svc.PutList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatDomains, Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Refresh(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if d, _ := svc.Test("ads.example"); !d.Blocked {
		t.Fatal("the name is not blocked after a refresh")
	}
	if err := svc.SetSettings(false, 60); err != nil {
		t.Fatal(err)
	}
	if d, _ := svc.Test("ads.example"); d.Blocked {
		t.Error("the name is still blocked with filtering off")
	}
	if err := svc.SetSettings(true, 60); err != nil {
		t.Fatal(err)
	}
	if d, _ := svc.Test("ads.example"); !d.Blocked {
		t.Error("re-enabling did not restore the snapshot")
	}
	// The list body was never deleted by the toggle.
	got, err := st.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Snapshot) != 1 {
		t.Errorf("Snapshot = %v, want the body untouched by the toggle", got.Snapshot)
	}
}

func TestTestReportsTheDecidingList(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	_, svc := newService(t, srv)
	id, err := svc.PutList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatDomains, Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Refresh(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	d, err := svc.Test("cdn.ads.example")
	if err != nil {
		t.Fatal(err)
	}
	if !d.Blocked || d.Policy != "l1" {
		t.Errorf("Test(cdn.ads.example) = %+v, want blocked by l1", d)
	}
	if d, err := svc.Test("example.org"); err != nil || d.Blocked || d.Policy != PolicyForwarded {
		t.Errorf("Test(example.org) = %+v %v, want forwarded", d, err)
	}
	if _, err := svc.Test("not a domain"); err == nil {
		t.Error("Test() accepted a malformed name")
	}
}

// Deleting a list must stop its blocks at once, not at the next refresh.
func TestDeletingAListStopsItsBlocks(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	_, svc := newService(t, srv)
	id, err := svc.PutList(store.BlacklistList{
		Name: "l1", URL: srv.URL, Format: FormatDomains, Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Refresh(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteList(id); err != nil {
		t.Fatal(err)
	}
	if d, _ := svc.Test("ads.example"); d.Blocked {
		t.Errorf("Test() = %+v after the list was deleted, want forwarded", d)
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `go test ./internal/policy/ -run TestPutList`
Expected: FAIL with "undefined: NewService".

- [ ] **Step 4: Write `internal/policy/service.go`**

```go
package policy

import (
	"context"
	"net/url"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// Refresh interval bounds. The floor keeps a misconfigured list from
// hammering a public source every tick.
const (
	minInterval     = 300
	defaultInterval = 86400
	maxBlockTTL     = 3600
)

// Service is the blacklist application service both transports call.
// Validation lives here so the JSON API, the CLI and the web UI cannot drift.
type Service struct {
	st *store.Store
	h  *Holder
	r  *Refresher
}

func NewService(st *store.Store, h *Holder, r *Refresher) *Service {
	return &Service{st: st, h: h, r: r}
}

func (s *Service) Settings() (store.BlacklistSettings, error) { return s.st.BlacklistSettings() }

// SetSettings applies the global toggle and block TTL, then rebuilds so the
// change takes effect without a restart.
func (s *Service) SetSettings(enabled bool, blockTTL int) error {
	if blockTTL < 1 || blockTTL > maxBlockTTL {
		return registry.Invalid("block_ttl", "block_ttl_range",
			"the block TTL must be between 1 and %d seconds", maxBlockTTL)
	}
	if err := s.st.SetBlacklistSettings(store.BlacklistSettings{Enabled: enabled, BlockTTL: blockTTL}); err != nil {
		return err
	}
	return s.h.Rebuild()
}

// Lists returns list metadata without the downloaded bodies.
func (s *Service) Lists() ([]store.BlacklistList, error) { return s.st.BlacklistListMetas() }

// PutList validates and writes a list definition, then rebuilds. A built-in
// may be enabled, disabled and re-tuned, but never renamed away from its
// manifest entry or re-pointed at a different URL.
func (s *Service) PutList(l store.BlacklistList) (int64, error) {
	l.Name = strings.ToLower(strings.TrimSpace(l.Name))
	l.URL = strings.TrimSpace(l.URL)
	l.Format = strings.ToLower(strings.TrimSpace(l.Format))
	l.Description = strings.TrimSpace(l.Description)

	if l.Name == "" {
		return 0, registry.Invalid("name", "name_required", "a list needs a name")
	}
	if err := validListURL(l.URL); err != nil {
		return 0, err
	}
	if l.Format == "" {
		l.Format = FormatDomains
	}
	if !ValidFormat(l.Format) {
		return 0, registry.Invalid("format", "format_unsupported",
			"format must be %s, %s or %s", FormatDomains, FormatHosts, FormatAdblock)
	}
	if l.IntervalSeconds == 0 {
		l.IntervalSeconds = defaultInterval
	}
	if l.IntervalSeconds < minInterval {
		return 0, registry.Invalid("interval_seconds", "interval_too_short",
			"the refresh interval must be at least %d seconds", minInterval)
	}

	if l.ID != 0 {
		cur, err := s.st.BlacklistListByID(l.ID)
		if err != nil {
			return 0, err
		}
		l.Builtin = cur.Builtin
		if cur.Builtin && (l.URL != cur.URL || l.Name != cur.Name) {
			return 0, registry.Invalid("url", "builtin_immutable",
				"a built-in list keeps its shipped name and URL; disable it instead")
		}
	} else {
		l.Builtin = false // only the manifest seeds built-ins
	}

	id, err := s.st.PutBlacklistList(l)
	if err != nil {
		return 0, err
	}
	return id, s.h.Rebuild()
}

func validListURL(raw string) error {
	if raw == "" {
		return registry.Invalid("url", "url_required", "a list needs a source URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return registry.Invalid("url", "url_invalid", "%q is not a URL", raw)
	}
	if u.Scheme != "https" {
		return registry.Invalid("url", "url_not_https",
			"a list URL must be https so the download can be verified")
	}
	if u.Host == "" {
		return registry.Invalid("url", "url_invalid", "%q has no host", raw)
	}
	return nil
}

func (s *Service) DeleteList(id int64) error {
	cur, err := s.st.BlacklistListByID(id)
	if err != nil {
		return err
	}
	if cur.Builtin {
		return registry.Invalid("id", "builtin_immutable",
			"a built-in list cannot be deleted; disable it instead")
	}
	if err := s.st.DeleteBlacklistList(id); err != nil {
		return err
	}
	return s.h.Rebuild()
}

func (s *Service) Rules() ([]store.BlacklistRule, error) { return s.st.BlacklistRules() }

// AddRule normalizes the domain and writes the rule. A duplicate or a
// conflicting rule of the other kind is refused by the store's unique index.
func (s *Service) AddRule(kind, domain string) (int64, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind != PolicyAllow && kind != PolicyDeny {
		return 0, registry.Invalid("kind", "kind_invalid", "a rule is either allow or deny")
	}
	n, err := Normalize(domain)
	if err != nil {
		return 0, registry.Invalid("domain", "domain_invalid", "%q is not a domain name", domain)
	}
	id, err := s.st.PutBlacklistRule(store.BlacklistRule{Kind: kind, Domain: n})
	if err != nil {
		return 0, err
	}
	return id, s.h.Rebuild()
}

func (s *Service) DeleteRule(id int64) error {
	if err := s.st.DeleteBlacklistRule(id); err != nil {
		return err
	}
	return s.h.Rebuild()
}

// Refresh downloads one list now, or every enabled list when id is 0.
func (s *Service) Refresh(ctx context.Context, id int64) error {
	if id == 0 {
		return s.r.RefreshAll(ctx)
	}
	return s.r.RefreshList(ctx, id)
}

// Test answers what the live policy would do with a name, without querying it.
func (s *Service) Test(name string) (Decision, error) {
	n, err := Normalize(name)
	if err != nil {
		return Decision{}, registry.Invalid("name", "name_invalid", "%q is not a domain name", name)
	}
	return s.h.Current().Decide(n), nil
}

// Counters reports blocked totals and counts by list. Never by client.
func (s *Service) Counters() (uint64, map[string]uint64) { return s.h.Counters() }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/policy/... ./internal/registry/... -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/registry/validate.go internal/policy/service.go internal/policy/service_test.go
git commit -m "feat(policy): validating blacklist service both transports call"
```

---

## Task 9: Admin API endpoints

**Files:**
- Create: `internal/adminapi/blacklists.go`
- Modify: `internal/adminapi/api.go:24-41` — `API` gains the policy service
- Modify: `internal/adminapi/api.go:88-126` — `Routes`
- Create: `internal/adminapi/blacklists_test.go`

**Interfaces:**
- Consumes: `*policy.Service` (Task 8).
- Produces:
  - `(*adminapi.API).WithPolicy(p *policy.Service) *API` — chainable, alongside `WithProviders`
  - Routes, all behind the same bearer-token `auth` wrapper as everything else:
    - `GET`/`PATCH` `/api/v1/blacklists/settings`
    - `GET`/`POST` `/api/v1/blacklists/lists`
    - `PATCH`/`DELETE` `/api/v1/blacklists/lists/{id}`
    - `POST` `/api/v1/blacklists/lists/{id}/refresh` — `{id}` may be `all`
    - `GET`/`POST` `/api/v1/blacklists/rules/{kind}`
    - `DELETE` `/api/v1/blacklists/rules/{kind}/{id}`
    - `GET` `/api/v1/blacklists/test?name=...`

**Note for the implementer:** the spec writes these paths without the `/api/v1` prefix. Every other endpoint in this codebase is versioned, so they are registered under `/api/v1/blacklists/...`.

- [ ] **Step 1: Write the failing test**

Create `internal/adminapi/blacklists_test.go`:

```go
package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/policy"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func newBlacklistAPI(t *testing.T) (http.Handler, string, *policy.Service) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	reg := registry.New(st, "home.arpa.", func() error { return nil })
	tok, err := reg.CreateToken("test")
	if err != nil {
		t.Fatal(err)
	}
	h := policy.NewHolder(func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		set, err := st.BlacklistSettings()
		if err != nil {
			return set, nil, nil, err
		}
		lists, err := st.BlacklistLists()
		if err != nil {
			return set, nil, nil, err
		}
		rules, err := st.BlacklistRules()
		return set, lists, rules, err
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	svc := policy.NewService(st, h, policy.NewRefresher(st, policy.NewFetcher(0), h, nil))
	api := NewAPI(reg, nil, nil).WithPolicy(svc)
	return api.Handler(), tok, svc
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", rec.Body, err)
	}
	return out
}

func TestBlacklistEndpointsRequireAToken(t *testing.T) {
	h, _, _ := newBlacklistAPI(t)
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/blacklists/settings"},
		{"PATCH", "/api/v1/blacklists/settings"},
		{"GET", "/api/v1/blacklists/lists"},
		{"POST", "/api/v1/blacklists/lists"},
		{"PATCH", "/api/v1/blacklists/lists/1"},
		{"DELETE", "/api/v1/blacklists/lists/1"},
		{"POST", "/api/v1/blacklists/lists/1/refresh"},
		{"GET", "/api/v1/blacklists/rules/deny"},
		{"POST", "/api/v1/blacklists/rules/deny"},
		{"DELETE", "/api/v1/blacklists/rules/deny/1"},
		{"GET", "/api/v1/blacklists/test?name=ads.example"},
	} {
		if rec := do(t, h, c.method, c.path, "", "{}"); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a token = %d, want 401", c.method, c.path, rec.Code)
		}
	}
}

func TestSettingsGetAndPatch(t *testing.T) {
	h, tok, _ := newBlacklistAPI(t)
	got := decodeBody(t, do(t, h, "GET", "/api/v1/blacklists/settings", tok, ""))
	if got["enabled"] != true || got["block_ttl"] != float64(60) {
		t.Errorf("GET settings = %v, want filtering on at 60s", got)
	}

	rec := do(t, h, "PATCH", "/api/v1/blacklists/settings", tok, `{"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH = %d: %s", rec.Code, rec.Body)
	}
	got = decodeBody(t, do(t, h, "GET", "/api/v1/blacklists/settings", tok, ""))
	// An omitted field keeps its value, exactly like PATCH /services/{id}.
	if got["enabled"] != false || got["block_ttl"] != float64(60) {
		t.Errorf("after PATCH = %v, want {false 60}", got)
	}

	if rec := do(t, h, "PATCH", "/api/v1/blacklists/settings", tok, `{"block_ttl":99999}`); rec.Code != http.StatusBadRequest {
		t.Errorf("PATCH with an out-of-range TTL = %d, want 400", rec.Code)
	}
}

func TestListCRUD(t *testing.T) {
	h, tok, _ := newBlacklistAPI(t)
	rec := do(t, h, "POST", "/api/v1/blacklists/lists", tok,
		`{"name":"custom","url":"https://lists.example/hosts","format":"hosts","enabled":true,"interval_seconds":3600}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body)
	}
	id := int64(decodeBody(t, rec)["id"].(float64))

	listed := decodeBody(t, do(t, h, "GET", "/api/v1/blacklists/lists", tok, ""))
	lists, _ := listed["lists"].([]any)
	if len(lists) != 1 {
		t.Fatalf("GET lists = %v, want one entry", listed)
	}
	first, _ := lists[0].(map[string]any)
	if first["name"] != "custom" || first["entry_count"] != float64(0) {
		t.Errorf("list = %v, want the created definition", first)
	}
	// A list body is never in an API response.
	if _, leaked := first["snapshot"]; leaked {
		t.Error("the list response carries the downloaded body")
	}

	path := "/api/v1/blacklists/lists/" + strconv.FormatInt(id, 10)
	if rec := do(t, h, "PATCH", path, tok, `{"enabled":false}`); rec.Code != http.StatusOK {
		t.Errorf("PATCH = %d: %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, "POST", "/api/v1/blacklists/lists", tok, `{"name":"bad","url":"http://x/y"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("POST with a plain-http URL = %d, want 400", rec.Code)
	}
	if rec := do(t, h, "DELETE", path, tok, ""); rec.Code != http.StatusNoContent {
		t.Errorf("DELETE = %d, want 204", rec.Code)
	}
	if rec := do(t, h, "DELETE", path, tok, ""); rec.Code != http.StatusNotFound {
		t.Errorf("second DELETE = %d, want 404", rec.Code)
	}
}

func TestRuleCRUDAndConflict(t *testing.T) {
	h, tok, _ := newBlacklistAPI(t)
	if rec := do(t, h, "POST", "/api/v1/blacklists/rules/deny", tok, `{"domain":"Ads.Example."}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST deny = %d: %s", rec.Code, rec.Body)
	}
	got := decodeBody(t, do(t, h, "GET", "/api/v1/blacklists/rules/deny", tok, ""))
	rules, _ := got["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("GET deny rules = %v, want one", got)
	}
	if r, _ := rules[0].(map[string]any); r["domain"] != "ads.example" {
		t.Errorf("rule = %v, want the normalized domain", rules[0])
	}
	// The allow list is a separate collection.
	empty := decodeBody(t, do(t, h, "GET", "/api/v1/blacklists/rules/allow", tok, ""))
	if a, _ := empty["rules"].([]any); len(a) != 0 {
		t.Errorf("GET allow rules = %v, want empty", empty)
	}
	if rec := do(t, h, "POST", "/api/v1/blacklists/rules/allow", tok, `{"domain":"ads.example"}`); rec.Code != http.StatusConflict {
		t.Errorf("conflicting rule = %d, want 409", rec.Code)
	}
	if rec := do(t, h, "POST", "/api/v1/blacklists/rules/deny", tok, `{"domain":"not a domain"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed domain = %d, want 400", rec.Code)
	}
	if rec := do(t, h, "DELETE", "/api/v1/blacklists/rules/deny/1", tok, ""); rec.Code != http.StatusNoContent {
		t.Errorf("DELETE = %d, want 204", rec.Code)
	}
}

func TestTestEndpointReportsTheDecision(t *testing.T) {
	h, tok, _ := newBlacklistAPI(t)
	if rec := do(t, h, "POST", "/api/v1/blacklists/rules/deny", tok, `{"domain":"ads.example"}`); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body)
	}
	got := decodeBody(t, do(t, h, "GET", "/api/v1/blacklists/test?name=cdn.ads.example", tok, ""))
	if got["blocked"] != true || got["policy"] != "deny" {
		t.Errorf("test = %v, want blocked by deny", got)
	}
	got = decodeBody(t, do(t, h, "GET", "/api/v1/blacklists/test?name=example.org", tok, ""))
	if got["blocked"] != false || got["policy"] != "forwarded" {
		t.Errorf("test = %v, want forwarded", got)
	}
	if rec := do(t, h, "GET", "/api/v1/blacklists/test?name=", tok, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("test with no name = %d, want 400", rec.Code)
	}
}

// A bad id is a client error. Without this, RefreshList's not-found error
// reports as 502 and reads as "the list host is down".
func TestRefreshUnknownListIs404(t *testing.T) {
	h, tok, _ := newBlacklistAPI(t)
	if rec := do(t, h, "POST", "/api/v1/blacklists/lists/999/refresh", tok, ""); rec.Code != http.StatusNotFound {
		t.Errorf("refresh of an unknown id = %d, want 404", rec.Code)
	}
}

// With no policy wired the endpoints answer cleanly rather than panicking.
func TestBlacklistEndpointsWithoutAPolicy(t *testing.T) {
	h, tok := newAPI(t)
	if rec := do(t, h, "GET", "/api/v1/blacklists/settings", tok, ""); rec.Code != http.StatusNotFound {
		t.Errorf("= %d, want 404 when filtering is not wired", rec.Code)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/adminapi/ -run Blacklist`
Expected: FAIL — `api.WithPolicy undefined`.

- [ ] **Step 3: Add the field and the routes**

In `internal/adminapi/api.go`, add `policy *policy.Service` to the `API` struct, import `"github.com/yoshiofthewire/kydns-server/internal/policy"`, and add below `WithProviders`:

```go
// WithPolicy attaches the blacklist service. It is optional, so the API still
// constructs where filtering is not running.
func (a *API) WithPolicy(p *policy.Service) *API {
	a.policy = p
	return a
}
```

At the end of `Routes`, after `POST /api/v1/cache/flush`:

```go
	mux.HandleFunc("GET /api/v1/blacklists/settings", auth(a.getBlacklistSettings))
	mux.HandleFunc("PATCH /api/v1/blacklists/settings", auth(a.patchBlacklistSettings))
	mux.HandleFunc("GET /api/v1/blacklists/lists", auth(a.listBlacklistLists))
	mux.HandleFunc("POST /api/v1/blacklists/lists", auth(a.createBlacklistList))
	mux.HandleFunc("PATCH /api/v1/blacklists/lists/{id}", auth(a.updateBlacklistList))
	mux.HandleFunc("DELETE /api/v1/blacklists/lists/{id}", auth(a.deleteBlacklistList))
	mux.HandleFunc("POST /api/v1/blacklists/lists/{id}/refresh", auth(a.refreshBlacklistList))
	mux.HandleFunc("GET /api/v1/blacklists/rules/{kind}", auth(a.listBlacklistRules))
	mux.HandleFunc("POST /api/v1/blacklists/rules/{kind}", auth(a.createBlacklistRule))
	mux.HandleFunc("DELETE /api/v1/blacklists/rules/{kind}/{id}", auth(a.deleteBlacklistRule))
	mux.HandleFunc("GET /api/v1/blacklists/test", auth(a.testBlacklist))
```

- [ ] **Step 4: Write `internal/adminapi/blacklists.go`**

```go
package adminapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/policy"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// blacklistListDTO is the wire form of a list. There is nowhere in it to put
// the downloaded body, which is how an export cannot carry one.
type blacklistListDTO struct {
	ID              int64  `json:"id,omitempty" yaml:"-"`
	Name            string `json:"name" yaml:"name"`
	URL             string `json:"url" yaml:"url"`
	Format          string `json:"format" yaml:"format"`
	Description     string `json:"description,omitempty" yaml:"description,omitempty"`
	Enabled         bool   `json:"enabled" yaml:"enabled"`
	Builtin         bool   `json:"builtin,omitempty" yaml:"builtin,omitempty"`
	IntervalSeconds int64  `json:"interval_seconds" yaml:"interval_seconds"`

	// Runtime state, reported but never imported.
	EntryCount    int    `json:"entry_count" yaml:"-"`
	SkippedCount  int    `json:"skipped_count" yaml:"-"`
	LastOKAt      int64  `json:"last_ok_at" yaml:"-"`
	LastAttemptAt int64  `json:"last_attempt_at" yaml:"-"`
	LastError     string `json:"last_error,omitempty" yaml:"-"`
}

type blacklistRuleDTO struct {
	ID     int64  `json:"id,omitempty" yaml:"-"`
	Kind   string `json:"kind" yaml:"kind"`
	Domain string `json:"domain" yaml:"domain"`
}

func toBlacklistListDTO(l store.BlacklistList) blacklistListDTO {
	return blacklistListDTO{
		ID: l.ID, Name: l.Name, URL: l.URL, Format: l.Format, Description: l.Description,
		Enabled: l.Enabled, Builtin: l.Builtin, IntervalSeconds: l.IntervalSeconds,
		EntryCount: l.EntryCount, SkippedCount: l.SkippedCount,
		LastOKAt: l.LastOKAt, LastAttemptAt: l.LastAttemptAt, LastError: l.LastError,
	}
}

func fromBlacklistListDTO(d blacklistListDTO) store.BlacklistList {
	return store.BlacklistList{
		ID: d.ID, Name: d.Name, URL: d.URL, Format: d.Format, Description: d.Description,
		Enabled: d.Enabled, Builtin: d.Builtin, IntervalSeconds: d.IntervalSeconds,
	}
}

// requirePolicy answers 404 rather than panicking where filtering is not wired.
func (a *API) requirePolicy(w http.ResponseWriter) bool {
	if a.policy == nil {
		writeErr(w, http.StatusNotFound, "not_found", "", "blacklist filtering is not enabled")
		return false
	}
	return true
}

func (a *API) getBlacklistSettings(w http.ResponseWriter, _ *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	set, err := a.policy.Settings()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": set.Enabled, "block_ttl": set.BlockTTL})
}

// patchBlacklistSettings merges onto the current settings: an omitted field
// keeps its value, matching PATCH /services/{id}.
func (a *API) patchBlacklistSettings(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	cur, err := a.policy.Settings()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	d := struct {
		Enabled  bool `json:"enabled"`
		BlockTTL int  `json:"block_ttl"`
	}{Enabled: cur.Enabled, BlockTTL: cur.BlockTTL}
	if !decode(w, r, &d) {
		return
	}
	if err := a.policy.SetSettings(d.Enabled, d.BlockTTL); err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": d.Enabled, "block_ttl": d.BlockTTL})
}

func (a *API) listBlacklistLists(w http.ResponseWriter, _ *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	lists, err := a.policy.Lists()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	out := make([]blacklistListDTO, 0, len(lists))
	for _, l := range lists {
		out = append(out, toBlacklistListDTO(l))
	}
	writeJSON(w, http.StatusOK, map[string]any{"lists": out})
}

func (a *API) createBlacklistList(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	d := blacklistListDTO{Enabled: true}
	if !decode(w, r, &d) {
		return
	}
	d.ID = 0
	id, err := a.policy.PutList(fromBlacklistListDTO(d))
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

// updateBlacklistList merges the body onto the current definition.
func (a *API) updateBlacklistList(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	lists, err := a.policy.Lists()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	var cur *store.BlacklistList
	for i := range lists {
		if lists[i].ID == id {
			cur = &lists[i]
		}
	}
	if cur == nil {
		writeErr(w, http.StatusNotFound, "not_found", "id", "no such list")
		return
	}
	d := toBlacklistListDTO(*cur)
	if !decode(w, r, &d) {
		return
	}
	d.ID = id
	if _, err := a.policy.PutList(fromBlacklistListDTO(d)); err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (a *API) deleteBlacklistList(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.policy.DeleteList(id); err != nil {
		writeRegistryErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// refreshBlacklistList downloads one list now. The id "all" refreshes every
// enabled list.
func (a *API) refreshBlacklistList(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	var id int64
	if r.PathValue("id") != "all" {
		var ok bool
		if id, ok = pathID(w, r); !ok {
			return
		}
	}
	// An unknown id is a client error, not an upstream one: RefreshList looks
	// the row up before it fetches anything.
	if err := a.policy.Refresh(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeRegistryErr(w, err)
			return
		}
		writeErr(w, http.StatusBadGateway, "refresh_failed", "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"refreshed": r.PathValue("id")})
}

func ruleKind(w http.ResponseWriter, r *http.Request) (string, bool) {
	kind := strings.ToLower(r.PathValue("kind"))
	if kind != policy.PolicyAllow && kind != policy.PolicyDeny {
		writeErr(w, http.StatusNotFound, "not_found", "kind", "a rule is either allow or deny")
		return "", false
	}
	return kind, true
}

func (a *API) listBlacklistRules(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	kind, ok := ruleKind(w, r)
	if !ok {
		return
	}
	rules, err := a.policy.Rules()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	out := []blacklistRuleDTO{}
	for _, rl := range rules {
		if rl.Kind == kind {
			out = append(out, blacklistRuleDTO{ID: rl.ID, Kind: rl.Kind, Domain: rl.Domain})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out})
}

func (a *API) createBlacklistRule(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	kind, ok := ruleKind(w, r)
	if !ok {
		return
	}
	var d struct {
		Domain string `json:"domain"`
	}
	if !decode(w, r, &d) {
		return
	}
	id, err := a.policy.AddRule(kind, d.Domain)
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (a *API) deleteBlacklistRule(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	if _, ok := ruleKind(w, r); !ok {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.policy.DeleteRule(id); err != nil {
		writeRegistryErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) testBlacklist(w http.ResponseWriter, r *http.Request) {
	if !a.requirePolicy(w) {
		return
	}
	name := r.URL.Query().Get("name")
	if strings.TrimSpace(name) == "" {
		writeErr(w, http.StatusBadRequest, "name_required", "name", "a name to test is required")
		return
	}
	d, err := a.policy.Test(name)
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "blocked": d.Blocked, "policy": d.Policy})
}
```

**Note:** the import block above lists only `net/http`, `strings`, `policy` and `store`. Drop `encoding/json` from it — `decode` and `writeJSON` in `api.go` do all the encoding.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/adminapi/... -v`
Expected: PASS, including every pre-existing API test.

- [ ] **Step 6: Commit**

```bash
git add internal/adminapi/
git commit -m "feat(api): blacklist settings, lists, rules, refresh and test endpoints"
```

---

## Task 10: Export and import the policy

**Files:**
- Modify: `internal/adminapi/api.go:74-78` — the `transfer` document
- Modify: `internal/adminapi/api.go:440-542` — `snapshotDoc` and `importDoc`
- Create: `internal/adminapi/blacklists_transfer_test.go`

**Interfaces:**
- Consumes: `blacklistListDTO`, `blacklistRuleDTO` (Task 9); `(*policy.Service)` methods (Task 8); `store.ReplaceBlacklist` (Task 3).
- Produces:
  - `transfer` gains `Blacklist *blacklistDoc` (`json:"blacklist,omitempty" yaml:"blacklist,omitempty"`)
  - `blacklistDoc{Enabled bool; BlockTTL int; Lists []blacklistListDTO; Rules []blacklistRuleDTO}`
  - `(*policy.Service).ReplacePolicy(set store.BlacklistSettings, lists []store.BlacklistList, rules []store.BlacklistRule) error` — validates everything before writing anything, then rebuilds

- [ ] **Step 1: Write the failing test**

Create `internal/adminapi/blacklists_transfer_test.go`:

```go
package adminapi

import (
	"net/http"
	"strings"
	"testing"
)

func TestExportCarriesPolicyButNeverListBodies(t *testing.T) {
	h, tok, _ := newBlacklistAPI(t)
	if rec := do(t, h, "POST", "/api/v1/blacklists/lists", tok,
		`{"name":"custom","url":"https://lists.example/hosts","format":"hosts","enabled":true,"interval_seconds":3600}`); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body)
	}
	if rec := do(t, h, "POST", "/api/v1/blacklists/rules/deny", tok, `{"domain":"ads.example"}`); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body)
	}

	rec := do(t, h, "GET", "/api/v1/export?format=json", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{"blacklist", "custom", "https://lists.example/hosts", "ads.example"} {
		if !strings.Contains(body, want) {
			t.Errorf("export is missing %q", want)
		}
	}
	// The downloaded body, the cache validators and the failure text are
	// runtime state, not backup content.
	for _, leak := range []string{"snapshot", "etag", "last_error", "last_ok_at"} {
		if strings.Contains(body, leak) {
			t.Errorf("export leaks %q", leak)
		}
	}
}

func TestImportReplaceRestoresThePolicy(t *testing.T) {
	h, tok, svc := newBlacklistAPI(t)
	doc := `{"views":[],"services":[],"records":[],"blacklist":{
	  "enabled":false,"block_ttl":30,
	  "lists":[{"name":"restored","url":"https://lists.example/x","format":"domains","enabled":true,"interval_seconds":3600}],
	  "rules":[{"kind":"deny","domain":"bad.example"},{"kind":"allow","domain":"good.example"}]}}`
	if rec := do(t, h, "POST", "/api/v1/import?mode=replace", tok, doc); rec.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", rec.Code, rec.Body)
	}
	set, err := svc.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if set.Enabled || set.BlockTTL != 30 {
		t.Errorf("settings = %+v, want {false 30}", set)
	}
	lists, err := svc.Lists()
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 1 || lists[0].Name != "restored" {
		t.Errorf("lists = %+v, want the imported definition", lists)
	}
	rules, err := svc.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Errorf("rules = %+v, want both imported rules", rules)
	}
}

// A bad document must leave the previous policy untouched, not half-applied.
func TestImportValidatesBeforeReplacing(t *testing.T) {
	h, tok, svc := newBlacklistAPI(t)
	if rec := do(t, h, "POST", "/api/v1/blacklists/rules/deny", tok, `{"domain":"keep.example"}`); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body)
	}
	bad := `{"views":[],"services":[],"records":[],"blacklist":{
	  "enabled":true,"block_ttl":60,
	  "lists":[{"name":"ok","url":"https://lists.example/x","format":"domains","enabled":true,"interval_seconds":3600},
	           {"name":"bad","url":"http://lists.example/y","format":"domains","enabled":true,"interval_seconds":3600}],
	  "rules":[]}}`
	if rec := do(t, h, "POST", "/api/v1/import?mode=replace", tok, bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("import of a plain-http list = %d, want 400", rec.Code)
	}
	rules, err := svc.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Domain != "keep.example" {
		t.Errorf("rules = %+v, want the prior policy untouched", rules)
	}
	lists, err := svc.Lists()
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 0 {
		t.Errorf("lists = %+v, want nothing written from the rejected document", lists)
	}
}

// Merge adds without wiping, and an omitted blacklist block changes nothing.
func TestImportMergeAddsAndOmissionChangesNothing(t *testing.T) {
	h, tok, svc := newBlacklistAPI(t)
	if rec := do(t, h, "POST", "/api/v1/blacklists/rules/deny", tok, `{"domain":"keep.example"}`); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body)
	}
	merge := `{"views":[],"services":[],"records":[],"blacklist":{
	  "enabled":true,"block_ttl":60,
	  "lists":[{"name":"added","url":"https://lists.example/x","format":"domains","enabled":true,"interval_seconds":3600}],
	  "rules":[{"kind":"deny","domain":"added.example"}]}}`
	if rec := do(t, h, "POST", "/api/v1/import?mode=merge", tok, merge); rec.Code != http.StatusOK {
		t.Fatalf("merge = %d: %s", rec.Code, rec.Body)
	}
	rules, err := svc.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Errorf("rules = %+v, want the existing rule kept and the new one added", rules)
	}

	if rec := do(t, h, "POST", "/api/v1/import?mode=merge", tok, `{"views":[],"services":[],"records":[]}`); rec.Code != http.StatusOK {
		t.Fatalf("merge with no blacklist block = %d", rec.Code)
	}
	after, err := svc.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 2 {
		t.Errorf("rules = %+v, want a document with no blacklist block to change nothing", after)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/adminapi/ -run Import`
Expected: FAIL — the export contains no `blacklist` key.

- [ ] **Step 3: Add `ReplacePolicy` to the service**

Append to `internal/policy/service.go`:

```go
// ReplacePolicy validates every list and rule before writing any of them, then
// writes them all in the one transaction store.ReplaceBlacklist opens and
// rebuilds once. Import --replace goes through here so a bad document can
// neither bypass the rules PutList enforces one at a time, nor leave the
// policy half-wiped.
func (s *Service) ReplacePolicy(set store.BlacklistSettings, lists []store.BlacklistList, rules []store.BlacklistRule) error {
	if set.BlockTTL < 1 || set.BlockTTL > maxBlockTTL {
		return registry.Invalid("block_ttl", "block_ttl_range",
			"the block TTL must be between 1 and %d seconds", maxBlockTTL)
	}
	ls := make([]store.BlacklistList, 0, len(lists))
	for _, l := range lists {
		v, err := s.validateList(l)
		if err != nil {
			return err
		}
		ls = append(ls, v)
	}
	rs := make([]store.BlacklistRule, 0, len(rules))
	for _, r := range rules {
		kind := strings.ToLower(strings.TrimSpace(r.Kind))
		if kind != PolicyAllow && kind != PolicyDeny {
			return registry.Invalid("kind", "kind_invalid", "a rule is either allow or deny")
		}
		n, err := Normalize(r.Domain)
		if err != nil {
			return registry.Invalid("domain", "domain_invalid", "%q is not a domain name", r.Domain)
		}
		rs = append(rs, store.BlacklistRule{Kind: kind, Domain: n})
	}
	if err := s.st.ReplaceBlacklist(set, ls, rs); err != nil {
		return err
	}
	return s.h.Rebuild()
}
```

- [ ] **Step 4: Factor the list validation out of `PutList`**

In `internal/policy/service.go`, extract the normalize-and-check block at the top of `PutList` into:

```go
// validateList normalizes and validates a list definition. It never touches
// the store, so ReplacePolicy can validate a whole document before writing
// any of it.
func (s *Service) validateList(l store.BlacklistList) (store.BlacklistList, error) {
	l.Name = strings.ToLower(strings.TrimSpace(l.Name))
	l.URL = strings.TrimSpace(l.URL)
	l.Format = strings.ToLower(strings.TrimSpace(l.Format))
	l.Description = strings.TrimSpace(l.Description)

	if l.Name == "" {
		return l, registry.Invalid("name", "name_required", "a list needs a name")
	}
	if err := validListURL(l.URL); err != nil {
		return l, err
	}
	if l.Format == "" {
		l.Format = FormatDomains
	}
	if !ValidFormat(l.Format) {
		return l, registry.Invalid("format", "format_unsupported",
			"format must be %s, %s or %s", FormatDomains, FormatHosts, FormatAdblock)
	}
	if l.IntervalSeconds == 0 {
		l.IntervalSeconds = defaultInterval
	}
	if l.IntervalSeconds < minInterval {
		return l, registry.Invalid("interval_seconds", "interval_too_short",
			"the refresh interval must be at least %d seconds", minInterval)
	}
	return l, nil
}
```

Then `PutList` becomes:

```go
func (s *Service) PutList(l store.BlacklistList) (int64, error) {
	l, err := s.validateList(l)
	if err != nil {
		return 0, err
	}
	if l.ID != 0 {
		cur, err := s.st.BlacklistListByID(l.ID)
		if err != nil {
			return 0, err
		}
		l.Builtin = cur.Builtin
		if cur.Builtin && (l.URL != cur.URL || l.Name != cur.Name) {
			return 0, registry.Invalid("url", "builtin_immutable",
				"a built-in list keeps its shipped name and URL; disable it instead")
		}
	} else {
		l.Builtin = false // only the manifest seeds built-ins
	}
	id, err := s.st.PutBlacklistList(l)
	if err != nil {
		return 0, err
	}
	return id, s.h.Rebuild()
}
```

- [ ] **Step 5: Add the document to `transfer`**

In `internal/adminapi/api.go`:

```go
// blacklistDoc is the exportable slice of filtering policy: settings, list
// definitions and one-off rules. Downloaded bodies and cache validators are
// runtime state and have no field here to live in.
type blacklistDoc struct {
	Enabled  bool               `json:"enabled" yaml:"enabled"`
	BlockTTL int                `json:"block_ttl" yaml:"block_ttl"`
	Lists    []blacklistListDTO `json:"lists" yaml:"lists"`
	Rules    []blacklistRuleDTO `json:"rules" yaml:"rules"`
}

// transfer is the export/import document. It carries no secrets by
// construction: there is nowhere in this struct to put one.
type transfer struct {
	Views     []viewDTO     `json:"views" yaml:"views"`
	Services  []serviceDTO  `json:"services" yaml:"services"`
	Records   []recordDTO   `json:"records" yaml:"records"`
	Blacklist *blacklistDoc `json:"blacklist,omitempty" yaml:"blacklist,omitempty"`
}
```

- [ ] **Step 6: Fill the document on export**

Append to `snapshotDoc`, before its `return`:

```go
	if a.policy != nil {
		set, err := a.policy.Settings()
		if err != nil {
			return doc, err
		}
		bl := &blacklistDoc{
			Enabled: set.Enabled, BlockTTL: set.BlockTTL,
			Lists: []blacklistListDTO{}, Rules: []blacklistRuleDTO{},
		}
		lists, err := a.policy.Lists()
		if err != nil {
			return doc, err
		}
		for _, l := range lists {
			// Definition only: the yaml tags drop every runtime field, and the
			// zero values keep them out of the JSON form too.
			bl.Lists = append(bl.Lists, blacklistListDTO{
				Name: l.Name, URL: l.URL, Format: l.Format, Description: l.Description,
				Enabled: l.Enabled, Builtin: l.Builtin, IntervalSeconds: l.IntervalSeconds,
			})
		}
		rules, err := a.policy.Rules()
		if err != nil {
			return doc, err
		}
		for _, r := range rules {
			bl.Rules = append(bl.Rules, blacklistRuleDTO{Kind: r.Kind, Domain: r.Domain})
		}
		doc.Blacklist = bl
	}
```

**Note for the implementer:** `blacklistListDTO`'s runtime fields carry `json:"entry_count"` and friends without `omitempty`, so they would appear in an export as zeroes. Add `,omitempty` to `EntryCount`, `SkippedCount`, `LastOKAt` and `LastAttemptAt` — the list endpoint's test in Task 9 asserts on `entry_count` being `0` for a fresh list, so change that assertion to check the key is absent instead:

```go
	if _, ok := first["entry_count"]; ok {
		t.Errorf("list = %v, want no entry count before the first refresh", first)
	}
```

- [ ] **Step 7: Apply the document on import**

In `importDoc`, inside the `mode == "replace"` branch, after `a.reg.ReplaceAll(...)` succeeds:

```go
		if err := a.applyBlacklistDoc(doc.Blacklist, true); err != nil {
			writeRegistryErr(w, err)
			return
		}
```

and at the end of the merge path, before its `writeJSON`:

```go
	if err := a.applyBlacklistDoc(doc.Blacklist, false); err != nil {
		writeRegistryErr(w, err)
		return
	}
```

Add to `internal/adminapi/blacklists.go`:

```go
// applyBlacklistDoc writes the imported policy. A document with no blacklist
// block changes nothing, so an older backup imports cleanly. Replace validates
// the whole policy before writing any of it; merge adds without wiping.
func (a *API) applyBlacklistDoc(doc *blacklistDoc, replace bool) error {
	if doc == nil || a.policy == nil {
		return nil
	}
	lists := make([]store.BlacklistList, 0, len(doc.Lists))
	for _, l := range doc.Lists {
		lists = append(lists, fromBlacklistListDTO(l))
	}
	rules := make([]store.BlacklistRule, 0, len(doc.Rules))
	for _, r := range doc.Rules {
		rules = append(rules, store.BlacklistRule{Kind: r.Kind, Domain: r.Domain})
	}
	if replace {
		return a.policy.ReplacePolicy(
			store.BlacklistSettings{Enabled: doc.Enabled, BlockTTL: doc.BlockTTL}, lists, rules)
	}
	if err := a.policy.SetSettings(doc.Enabled, doc.BlockTTL); err != nil {
		return err
	}
	for _, l := range lists {
		if _, err := a.policy.PutList(l); err != nil {
			return err
		}
	}
	for _, r := range rules {
		if _, err := a.policy.AddRule(r.Kind, r.Domain); err != nil {
			return err
		}
	}
	return nil
}
```

**Ordering:** call `applyBlacklistDoc` **after** `a.reg.ReplaceAll` in the replace branch, exactly as written above. `ReplacePolicy` validates the whole policy before it wipes anything, so a bad blacklist block leaves the previous policy intact regardless of order — that is what `TestImportValidatesBeforeReplacing` checks. The registry and the policy are still two separate transactions: a failure between them leaves the registry replaced and the policy not. Say so in the response rather than pretending otherwise — the `writeRegistryErr` call already returns the underlying error, and the operator re-imports.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `go test ./internal/adminapi/... ./internal/policy/... -v`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/adminapi/ internal/policy/service.go
git commit -m "feat(api): export and import blacklist policy without list bodies"
```

---

## Task 11: The `kydns blacklist` command family

**Files:**
- Create: `internal/cli/blacklist.go`
- Modify: `internal/cli/cli.go:85-101` — the `Run` switch
- Create: `internal/cli/blacklist_test.go`

**Interfaces:**
- Consumes: the Task 9 endpoints over HTTP.
- Produces the subcommands:
  - `kydns blacklist status`
  - `kydns blacklist on` / `kydns blacklist off`
  - `kydns blacklist list`
  - `kydns blacklist add <name> --url <https url> [--format domains|hosts|adblock] [--interval seconds]`
  - `kydns blacklist rm <id>`
  - `kydns blacklist refresh [id|all]`
  - `kydns blacklist allow <domain>` / `kydns blacklist deny <domain>`
  - `kydns blacklist rules [allow|deny]`
  - `kydns blacklist unrule <allow|deny> <id>`
  - `kydns blacklist test <name>`

- [ ] **Step 1: Write the failing test**

Create `internal/cli/blacklist_test.go`:

```go
package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// blacklistServer records what the CLI sent and replies with canned JSON.
func blacklistServer(t *testing.T, routes map[string]string) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		body.ReadFrom(r.Body)
		seen = append(seen, r.Method+" "+r.URL.RequestURI()+" "+strings.TrimSpace(body.String()))
		w.Header().Set("Content-Type", "application/json")
		if reply, ok := routes[r.Method+" "+r.URL.Path]; ok {
			w.Write([]byte(reply))
			return
		}
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("KYDNS_URL", srv.URL)
	t.Setenv("KYDNS_TOKEN", "kydns_test")
	return srv, &seen
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestBlacklistStatus(t *testing.T) {
	_, seen := blacklistServer(t, map[string]string{
		"GET /api/v1/blacklists/settings": `{"enabled":true,"block_ttl":60}`,
		"GET /api/v1/blacklists/lists":    `{"lists":[{"id":1,"name":"steven-black","entry_count":3,"last_error":""}]}`,
	})
	code, out, errOut := runCLI(t, "blacklist", "status")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"on", "60", "steven-black", "3"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q:\n%s", want, out)
		}
	}
	_ = seen
}

func TestBlacklistOffSendsPatch(t *testing.T) {
	_, seen := blacklistServer(t, nil)
	if code, _, errOut := runCLI(t, "blacklist", "off"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if len(*seen) != 1 || !strings.HasPrefix((*seen)[0], "PATCH /api/v1/blacklists/settings") {
		t.Fatalf("sent %v, want one PATCH", *seen)
	}
	if !strings.Contains((*seen)[0], `"enabled":false`) {
		t.Errorf("body = %q, want enabled false", (*seen)[0])
	}
}

func TestBlacklistAddRequiresAnHTTPSURL(t *testing.T) {
	blacklistServer(t, nil)
	if code, _, _ := runCLI(t, "blacklist", "add", "custom"); code == 0 {
		t.Error("add without --url succeeded")
	}
	if code, _, _ := runCLI(t, "blacklist", "add", "custom", "--url", "http://x/y"); code == 0 {
		t.Error("add with a plain-http URL succeeded")
	}
}

func TestBlacklistAddSendsTheDefinition(t *testing.T) {
	_, seen := blacklistServer(t, map[string]string{
		"POST /api/v1/blacklists/lists": `{"id":7}`,
	})
	code, out, errOut := runCLI(t, "blacklist", "add", "custom",
		"--url", "https://lists.example/hosts", "--format", "hosts", "--interval", "3600")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "custom") {
		t.Errorf("output = %q, want the list named", out)
	}
	sent := (*seen)[0]
	for _, want := range []string{`"name":"custom"`, `"url":"https://lists.example/hosts"`, `"format":"hosts"`, `"interval_seconds":3600`} {
		if !strings.Contains(sent, want) {
			t.Errorf("body %q missing %s", sent, want)
		}
	}
}

func TestBlacklistRuleCommands(t *testing.T) {
	_, seen := blacklistServer(t, map[string]string{
		"POST /api/v1/blacklists/rules/deny": `{"id":3}`,
		"GET /api/v1/blacklists/rules/deny":  `{"rules":[{"id":3,"kind":"deny","domain":"ads.example"}]}`,
		"GET /api/v1/blacklists/rules/allow": `{"rules":[]}`,
	})
	if code, _, errOut := runCLI(t, "blacklist", "deny", "ads.example"); code != 0 {
		t.Fatalf("deny: %s", errOut)
	}
	if !strings.Contains((*seen)[0], `"domain":"ads.example"`) {
		t.Errorf("sent %q", (*seen)[0])
	}
	code, out, errOut := runCLI(t, "blacklist", "rules")
	if code != 0 {
		t.Fatalf("rules: %s", errOut)
	}
	if !strings.Contains(out, "ads.example") || !strings.Contains(out, "deny") {
		t.Errorf("rules output = %q", out)
	}
}

func TestBlacklistTest(t *testing.T) {
	blacklistServer(t, map[string]string{
		"GET /api/v1/blacklists/test": `{"name":"ads.example","blocked":true,"policy":"steven-black"}`,
	})
	code, out, errOut := runCLI(t, "blacklist", "test", "ads.example")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "blocked") || !strings.Contains(out, "steven-black") {
		t.Errorf("test output = %q, want the blocking list named", out)
	}
}

func TestBlacklistRefreshAll(t *testing.T) {
	_, seen := blacklistServer(t, nil)
	if code, _, errOut := runCLI(t, "blacklist", "refresh"); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.HasPrefix((*seen)[0], "POST /api/v1/blacklists/lists/all/refresh") {
		t.Errorf("sent %q, want the all-lists refresh", (*seen)[0])
	}
}

func TestBlacklistUnknownSubcommand(t *testing.T) {
	blacklistServer(t, nil)
	if code, _, _ := runCLI(t, "blacklist", "frobnicate"); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/cli/ -run Blacklist`
Expected: FAIL — `blacklist` is an unknown subcommand, exit 2.

- [ ] **Step 3: Add the dispatch**

In `internal/cli/cli.go`, in `Run`'s switch, after `case "record":`:

```go
	case "blacklist":
		return blacklistCmd(c, args[1:], stdout, stderr)
```

- [ ] **Step 4: Write `internal/cli/blacklist.go`**

```go
package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

const blacklistUsage = `usage:
  kydns blacklist status
  kydns blacklist on|off
  kydns blacklist list
  kydns blacklist add <name> --url <https url> [--format domains|hosts|adblock] [--interval seconds]
  kydns blacklist rm <id>
  kydns blacklist refresh [id|all]
  kydns blacklist allow|deny <domain>
  kydns blacklist rules [allow|deny]
  kydns blacklist unrule <allow|deny> <id>
  kydns blacklist test <name>`

type blacklistListRow struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	URL             string `json:"url"`
	Format          string `json:"format"`
	Enabled         bool   `json:"enabled"`
	Builtin         bool   `json:"builtin"`
	IntervalSeconds int64  `json:"interval_seconds"`
	EntryCount      int    `json:"entry_count"`
	SkippedCount    int    `json:"skipped_count"`
	LastOKAt        int64  `json:"last_ok_at"`
	LastError       string `json:"last_error"`
}

type blacklistSettings struct {
	Enabled  bool `json:"enabled"`
	BlockTTL int  `json:"block_ttl"`
}

func blacklistCmd(c *Client, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, blacklistUsage)
		return 2
	}
	switch args[0] {
	case "status":
		return blacklistStatus(c, stdout, stderr)
	case "on", "off":
		if err := c.Do("PATCH", "/api/v1/blacklists/settings",
			map[string]any{"enabled": args[0] == "on"}, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "filtering %s\n", args[0])
		return 0
	case "list":
		return blacklistList(c, stdout, stderr)
	case "add":
		return blacklistAdd(c, args[1:], stdout, stderr)
	case "rm":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "usage: kydns blacklist rm <id>")
			return 2
		}
		if err := c.Do("DELETE", "/api/v1/blacklists/lists/"+args[1], nil, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "removed list %s\n", args[1])
		return 0
	case "refresh":
		target := "all"
		if len(args) == 2 {
			target = args[1]
		}
		if err := c.Do("POST", "/api/v1/blacklists/lists/"+target+"/refresh", nil, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "refreshed %s\n", target)
		return 0
	case "allow", "deny":
		if len(args) != 2 {
			fmt.Fprintf(stderr, "usage: kydns blacklist %s <domain>\n", args[0])
			return 2
		}
		if err := c.Do("POST", "/api/v1/blacklists/rules/"+args[0],
			map[string]any{"domain": args[1]}, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "added %s rule for %s\n", args[0], args[1])
		return 0
	case "rules":
		kinds := []string{"deny", "allow"}
		if len(args) == 2 {
			kinds = []string{args[1]}
		}
		return blacklistRules(c, kinds, stdout, stderr)
	case "unrule":
		if len(args) != 3 {
			fmt.Fprintln(stderr, "usage: kydns blacklist unrule <allow|deny> <id>")
			return 2
		}
		if err := c.Do("DELETE", "/api/v1/blacklists/rules/"+args[1]+"/"+args[2], nil, nil); err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "removed %s rule %s\n", args[1], args[2])
		return 0
	case "test":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "usage: kydns blacklist test <name>")
			return 2
		}
		var out struct {
			Name    string `json:"name"`
			Blocked bool   `json:"blocked"`
			Policy  string `json:"policy"`
		}
		if err := c.Do("GET", "/api/v1/blacklists/test?name="+args[1], nil, &out); err != nil {
			return fail(stderr, err)
		}
		if out.Blocked {
			fmt.Fprintf(stdout, "%s: blocked by %s\n", out.Name, out.Policy)
			return 0
		}
		fmt.Fprintf(stdout, "%s: allowed (%s)\n", out.Name, out.Policy)
		return 0
	}
	fmt.Fprintf(stderr, "kydns: unknown blacklist subcommand %q\n", args[0])
	return 2
}

func blacklistStatus(c *Client, stdout, stderr io.Writer) int {
	var set blacklistSettings
	if err := c.Do("GET", "/api/v1/blacklists/settings", nil, &set); err != nil {
		return fail(stderr, err)
	}
	state := "off"
	if set.Enabled {
		state = "on"
	}
	fmt.Fprintf(stdout, "filtering %s, blocks cached for %ds\n", state, set.BlockTTL)
	return blacklistList(c, stdout, stderr)
}

func blacklistList(c *Client, stdout, stderr io.Writer) int {
	var out struct {
		Lists []blacklistListRow `json:"lists"`
	}
	if err := c.Do("GET", "/api/v1/blacklists/lists", nil, &out); err != nil {
		return fail(stderr, err)
	}
	for _, l := range out.Lists {
		state := "off"
		if l.Enabled {
			state = "on"
		}
		note := ""
		switch {
		// "Never loaded" is checked first: a list that has failed and has never
		// succeeded has no snapshot to be stale, and calling it stale would
		// claim it is still filtering when it is not.
		case l.LastOKAt == 0:
			note = " never loaded"
		case l.LastError != "":
			// A stale snapshot is still serving; say so rather than "broken".
			note = " stale: " + l.LastError
		}
		fmt.Fprintf(stdout, "%-6d %-20s %-4s %-8s %7d entries%s\n",
			l.ID, l.Name, state, l.Format, l.EntryCount, note)
	}
	return 0
}

func blacklistAdd(c *Client, args []string, stdout, stderr io.Writer) int {
	const usage = "usage: kydns blacklist add <name> --url <https url> [--format domains|hosts|adblock] [--interval seconds]"
	// The documented form puts the name before the flags, but flag.Parse stops
	// at the first positional. Peel the name off first.
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	name := args[0]
	fs := flag.NewFlagSet("blacklist add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", "", "https source URL")
	format := fs.String("format", "domains", "domains, hosts or adblock")
	interval := fs.Int64("interval", 86400, "seconds between refreshes")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *url == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	// Checked here as well as on the server, so a typo fails before it is sent.
	if !strings.HasPrefix(*url, "https://") {
		fmt.Fprintln(stderr, "kydns: a list URL must be https")
		return 1
	}
	body := map[string]any{
		"name": name, "url": *url, "format": *format,
		"enabled": true, "interval_seconds": *interval,
	}
	if err := c.Do("POST", "/api/v1/blacklists/lists", body, nil); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "added list %s\n", name)
	return 0
}

func blacklistRules(c *Client, kinds []string, stdout, stderr io.Writer) int {
	for _, kind := range kinds {
		var out struct {
			Rules []struct {
				ID     int64  `json:"id"`
				Kind   string `json:"kind"`
				Domain string `json:"domain"`
			} `json:"rules"`
		}
		if err := c.Do("GET", "/api/v1/blacklists/rules/"+kind, nil, &out); err != nil {
			return fail(stderr, err)
		}
		for _, r := range out.Rules {
			fmt.Fprintf(stdout, "%-6d %-6s %s\n", r.ID, r.Kind, r.Domain)
		}
	}
	return 0
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/cli/... -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/
git commit -m "feat(cli): kydns blacklist command family"
```

---

## Task 12: The Blacklists tab

**Files:**
- Create: `internal/web/blacklists.go`
- Create: `internal/web/templates/blacklists.html`
- Modify: `internal/web/pages.go:5-11` and `:14-39` — register the page and its routes
- Modify: `internal/web/templates/layout.html:8` — the nav link
- Modify: `internal/web/middleware.go:20-38` — `Options` gains `Policy *policy.Service`
- Create: `internal/web/blacklists_test.go`

**Interfaces:**
- Consumes: `*policy.Service` (Tasks 8 and 10).
- Produces:
  - `web.Options.Policy *policy.Service` — nil renders "filtering is not enabled"
  - Routes: `GET /blacklists`; `POST /blacklists/toggle`, `/blacklists/lists/new`, `/blacklists/lists/toggle`, `/blacklists/lists/delete`, `/blacklists/refresh`, `/blacklists/rules/new`, `/blacklists/rules/delete`, `/blacklists/test`

- [ ] **Step 1: Write the failing test**

Create `internal/web/blacklists_test.go`:

```go
package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestBlacklistsTabIsLinkedAndRequiresASession(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	if !strings.Contains(page(t, h, "/services", c), `href="/blacklists"`) {
		t.Error("the navigation has no Blacklists link")
	}
	rec := get(t, h, "/blacklists", nil)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("anonymous GET /blacklists = %d, want a redirect to login", rec.Code)
	}
}

func TestBlacklistsPageShowsStateAndWarnings(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	body := page(t, h, "/blacklists", c)
	for _, want := range []string{"Blacklists", "steven-black", "never loaded"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	// Filtering is on by default, so the "filtering is off" warning must not
	// be showing.
	if strings.Contains(body, "Filtering is off") {
		t.Error("the disabled warning shows while filtering is on")
	}
}

func TestTogglingFilteringOffWarnsOnThePage(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/blacklists/toggle", url.Values{"csrf_token": {csrf}}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("toggle = %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(page(t, h, "/blacklists", c), "Filtering is off") {
		t.Error("no warning after filtering was turned off")
	}
	// Toggling back on clears it, and nothing was deleted.
	if rec := postForm(t, h, "/blacklists/toggle", url.Values{"csrf_token": {csrf}}, c); rec.Code != http.StatusSeeOther {
		t.Fatal(rec.Body)
	}
	body := page(t, h, "/blacklists", c)
	if strings.Contains(body, "Filtering is off") {
		t.Error("the warning survived re-enabling")
	}
	if !strings.Contains(body, "steven-black") {
		t.Error("re-enabling lost the lists")
	}
}

func TestAddingAndRemovingACustomList(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/blacklists/lists/new", url.Values{
		"name": {"custom"}, "url": {"https://lists.example/hosts"},
		"format": {"hosts"}, "interval": {"3600"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("new list = %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(page(t, h, "/blacklists", c), "custom") {
		t.Fatal("the new list is not on the page")
	}

	// A plain-http URL is refused with the message on the page, not a bare 500.
	rec = postForm(t, h, "/blacklists/lists/new", url.Values{
		"name": {"bad"}, "url": {"http://lists.example/hosts"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "https") {
		t.Errorf("plain-http list = %d: %s", rec.Code, rec.Body)
	}
}

func TestBuiltinListCannotBeDeletedFromTheUI(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	lists, err := srv.o.Policy.Lists()
	if err != nil {
		t.Fatal(err)
	}
	var builtinID int64
	for _, l := range lists {
		if l.Builtin {
			builtinID = l.ID
		}
	}
	if builtinID == 0 {
		t.Fatal("no built-in list was seeded")
	}
	rec := postForm(t, h, "/blacklists/lists/delete", url.Values{
		"id": {itoa(builtinID)}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("deleting a built-in = %d, want 400", rec.Code)
	}
	if !strings.Contains(page(t, h, "/blacklists", c), "steven-black") {
		t.Error("the built-in was removed")
	}
}

func TestOneOffRulesRoundTripAndRejectConflicts(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/blacklists/rules/new", url.Values{
		"kind": {"deny"}, "domain": {"Ads.Example."}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("new rule = %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(page(t, h, "/blacklists", c), "ads.example") {
		t.Error("the normalized rule is not on the page")
	}
	rec = postForm(t, h, "/blacklists/rules/new", url.Values{
		"kind": {"allow"}, "domain": {"ads.example"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("conflicting rule = %d, want the page to refuse it", rec.Code)
	}
}

func TestTestBoxNamesTheDecidingRule(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	if rec := postForm(t, h, "/blacklists/rules/new", url.Values{
		"kind": {"deny"}, "domain": {"ads.example"}, "csrf_token": {csrf},
	}, c); rec.Code != http.StatusSeeOther {
		t.Fatal(rec.Body)
	}
	rec := postForm(t, h, "/blacklists/test", url.Values{
		"name": {"cdn.ads.example"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("test = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "cdn.ads.example") || !strings.Contains(body, "deny") {
		t.Errorf("test result = %q, want the name and the deciding rule", body)
	}
}

// Every mutating route must be CSRF-protected, like every other form.
func TestBlacklistFormsRequireCSRF(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	for _, path := range []string{
		"/blacklists/toggle", "/blacklists/lists/new", "/blacklists/lists/toggle",
		"/blacklists/lists/delete", "/blacklists/refresh",
		"/blacklists/rules/new", "/blacklists/rules/delete", "/blacklists/test",
	} {
		if rec := postForm(t, h, path, url.Values{"csrf_token": {"wrong"}}, c); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s with a bad token = %d, want 403", path, rec.Code)
		}
	}
}
```

Add the small helper the test uses, at the bottom of `internal/web/blacklists_test.go`:

```go
func itoa(n int64) string { return strconv.FormatInt(n, 10) }
```

with `"strconv"` in the imports.

- [ ] **Step 2: Extend the web test harness**

In `internal/web/auth_test.go`, inside `newWeb`, after `reg := registry.New(...)`, wire a policy service so every web test has one:

```go
	ph := policy.NewHolder(func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		set, err := st.BlacklistSettings()
		if err != nil {
			return set, nil, nil, err
		}
		lists, err := st.BlacklistLists()
		if err != nil {
			return set, nil, nil, err
		}
		rules, err := st.BlacklistRules()
		return set, lists, rules, err
	})
	if err := policy.SeedBuiltins(st); err != nil {
		t.Fatal(err)
	}
	if err := ph.Rebuild(); err != nil {
		t.Fatal(err)
	}
	pol := policy.NewService(st, ph, policy.NewRefresher(st, policy.NewFetcher(2*time.Second), ph, nil))
```

and add `Policy: pol,` to the `Options` literal, plus `API: adminapi.NewAPI(reg, acl, cache).WithPolicy(pol),`.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/web/ -run Blacklist`
Expected: FAIL — `unknown field Policy in struct literal`.

- [ ] **Step 4: Add the option and the routes**

In `internal/web/middleware.go`, add to `Options`:

```go
	// Policy is nil when filtering is not wired, which the screen renders as
	// "not enabled" rather than as an empty tab.
	Policy *policy.Service
```

with `"github.com/yoshiofthewire/kydns-server/internal/policy"` imported.

In `internal/web/pages.go`, add `registerPage("blacklists.html")` to `init`, and to `pageRoutes`:

```go
	mux.HandleFunc("GET /blacklists", s.requireSession(s.getBlacklists))
	mux.HandleFunc("POST /blacklists/toggle", s.requireCSRF(s.postBlacklistToggle))
	mux.HandleFunc("POST /blacklists/lists/new", s.requireCSRF(s.postBlacklistListNew))
	mux.HandleFunc("POST /blacklists/lists/toggle", s.requireCSRF(s.postBlacklistListToggle))
	mux.HandleFunc("POST /blacklists/lists/delete", s.requireCSRF(s.postBlacklistListDelete))
	mux.HandleFunc("POST /blacklists/refresh", s.requireCSRF(s.postBlacklistRefresh))
	mux.HandleFunc("POST /blacklists/rules/new", s.requireCSRF(s.postBlacklistRuleNew))
	mux.HandleFunc("POST /blacklists/rules/delete", s.requireCSRF(s.postBlacklistRuleDelete))
	mux.HandleFunc("POST /blacklists/test", s.requireCSRF(s.postBlacklistTest))
```

In `internal/web/templates/layout.html`, after the Records link:

```html
    <a href="/blacklists"{{if eq .Nav "blacklists"}} aria-current="page"{{end}}>Blacklists</a>
```

- [ ] **Step 5: Write `internal/web/blacklists.go`**

> **Correction applied during implementation (commit 02eb6aa).** The
> `blacklistsData` below guards later error assignments with
> `data["Error"] == nil`. That never fires: `data["Error"]` already holds a
> string (possibly empty), and a string is never nil as an interface, so a
> `Lists()` or `Rules()` failure after a successful `Settings()` call is
> silently swallowed and the screen renders as if nothing went wrong. The
> shipped code uses a plain `errMsg string` accumulator and assigns
> `data["Error"] = errMsg` once at the end, mirroring `settingsData`. Read
> `internal/web/blacklists.go` for the authoritative version.

```go
package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// blacklistRow is one list as the table shows it. Status is the plain-language
// state an operator acts on, not a raw error.
type blacklistRow struct {
	ID           int64
	Name         string
	Description  string
	URL          string
	Format       string
	Enabled      bool
	Builtin      bool
	Interval     string
	Entries      int
	Skipped      int
	LastOK       string
	Stale        bool
	NeverLoaded  bool
	LastError    string
}

func agoOrNever(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04 UTC")
}

func (s *Server) blacklistsData(errMsg string, result map[string]any) map[string]any {
	data := map[string]any{
		"Title": "Blacklists", "Nav": "blacklists", "Error": errMsg, "Result": result,
	}
	if s.o.Policy == nil {
		data["Unavailable"] = true
		return data
	}

	set, err := s.o.Policy.Settings()
	if err != nil && errMsg == "" {
		data["Error"] = err.Error()
	}
	data["Enabled"] = set.Enabled
	data["BlockTTL"] = set.BlockTTL

	lists, err := s.o.Policy.Lists()
	if err != nil && data["Error"] == nil {
		data["Error"] = err.Error()
	}
	rows := make([]blacklistRow, 0, len(lists))
	staleAny := false
	for _, l := range lists {
		row := blacklistRow{
			ID: l.ID, Name: l.Name, Description: l.Description, URL: l.URL,
			Format: l.Format, Enabled: l.Enabled, Builtin: l.Builtin,
			Interval: strconv.FormatInt(l.IntervalSeconds/60, 10) + " min",
			Entries:  l.EntryCount, Skipped: l.SkippedCount,
			LastOK:   agoOrNever(l.LastOKAt),
			// A failed refresh does not stop the list working: the last good
			// snapshot is still in force, so this reads "stale", not "broken".
			Stale:       l.LastError != "" && l.LastOKAt != 0,
			NeverLoaded: l.LastOKAt == 0,
			LastError:   l.LastError,
		}
		if row.Stale || (row.NeverLoaded && l.Enabled) {
			staleAny = true
		}
		rows = append(rows, row)
	}
	data["Lists"] = rows
	data["StaleAny"] = staleAny

	rules, err := s.o.Policy.Rules()
	if err != nil && data["Error"] == nil {
		data["Error"] = err.Error()
	}
	var allow, deny []store.BlacklistRule
	for _, r := range rules {
		if r.Kind == "allow" {
			allow = append(allow, r)
			continue
		}
		deny = append(deny, r)
	}
	data["Allow"], data["Deny"] = allow, deny

	total, byList := s.o.Policy.Counters()
	data["BlockedTotal"] = total
	data["BlockedByList"] = byList
	return data
}

func (s *Server) getBlacklists(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "blacklists.html", s.blacklistsData("", nil))
}

// blacklistsError re-renders the page with a field-level message rather than
// replacing it with a bare error page.
func (s *Server) blacklistsError(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, r, "blacklists.html", s.blacklistsData(err.Error(), nil))
}

func (s *Server) requirePolicy(w http.ResponseWriter) bool {
	if s.o.Policy == nil {
		http.Error(w, "blacklist filtering is not enabled", http.StatusNotFound)
		return false
	}
	return true
}

// postBlacklistToggle flips the global switch. It deletes nothing: turning
// filtering back on restores every list and rule immediately.
func (s *Server) postBlacklistToggle(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	set, err := s.o.Policy.Settings()
	if err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	if err := s.o.Policy.SetSettings(!set.Enabled, set.BlockTTL); err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/blacklists", http.StatusSeeOther)
}

func (s *Server) postBlacklistListNew(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	interval, _ := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("interval")), 10, 64)
	l := store.BlacklistList{
		Name:            r.PostFormValue("name"),
		URL:             r.PostFormValue("url"),
		Format:          r.PostFormValue("format"),
		Enabled:         true,
		IntervalSeconds: interval,
	}
	if _, err := s.o.Policy.PutList(l); err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/blacklists", http.StatusSeeOther)
}

// postBlacklistListToggle enables or disables one list, leaving its downloaded
// body alone.
func (s *Server) postBlacklistListToggle(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	lists, err := s.o.Policy.Lists()
	if err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	for _, l := range lists {
		if l.ID != id {
			continue
		}
		l.Enabled = !l.Enabled
		if _, err := s.o.Policy.PutList(l); err != nil {
			s.blacklistsError(w, r, err)
			return
		}
		http.Redirect(w, r, "/blacklists", http.StatusSeeOther)
		return
	}
	s.blacklistsError(w, r, errNoSuchList)
}

func (s *Server) postBlacklistListDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err == nil {
		err = s.o.Policy.DeleteList(id)
	}
	if err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/blacklists", http.StatusSeeOther)
}

// postBlacklistRefresh downloads one list, or every list when no id is given.
func (s *Server) postBlacklistRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	id, _ := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err := s.o.Policy.Refresh(r.Context(), id); err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/blacklists", http.StatusSeeOther)
}

func (s *Server) postBlacklistRuleNew(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	if _, err := s.o.Policy.AddRule(r.PostFormValue("kind"), r.PostFormValue("domain")); err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/blacklists", http.StatusSeeOther)
}

func (s *Server) postBlacklistRuleDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err == nil {
		err = s.o.Policy.DeleteRule(id)
	}
	if err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/blacklists", http.StatusSeeOther)
}

// postBlacklistTest renders the page directly rather than redirecting, because
// the result exists only in this response.
func (s *Server) postBlacklistTest(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	d, err := s.o.Policy.Test(name)
	if err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	s.render(w, r, "blacklists.html", s.blacklistsData("", map[string]any{
		"Name": name, "Blocked": d.Blocked, "Policy": d.Policy,
	}))
}
```

Add near the top of the file:

```go
var errNoSuchList = errors.New("no such list")
```

with `"errors"` imported.

- [ ] **Step 6: Write `internal/web/templates/blacklists.html`**

```html
{{define "page"}}
{{if .Unavailable}}
<div class="card">
  <p class="muted">Blacklist filtering is not enabled on this server.</p>
</div>
{{else}}

<div class="card">
  <h3>Filtering</h3>
  {{if .Enabled}}
    <p>Filtering is <span class="badge accent">on</span>. Blocked names are
       answered locally with NXDOMAIN and never sent to an upstream. Blocks are
       cached by clients for {{.BlockTTL}} seconds.</p>
  {{else}}
    <p class="error">Filtering is off. Nothing is being blocked. Your lists and
       rules are still here — turning filtering back on restores them at once.</p>
  {{end}}
  <p class="muted">This is domain filtering. KyDNS does not inspect URLs, TLS,
     page content, or client traffic, and it is not a malware guarantee.</p>
  <div class="address-row">
    <form method="post" action="/blacklists/toggle">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <button type="submit">{{if .Enabled}}Turn filtering off{{else}}Turn filtering on{{end}}</button>
    </form>
    <form method="post" action="/blacklists/refresh">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <button class="ghost" type="submit">Refresh all lists</button>
    </form>
  </div>
  <p class="muted">{{.BlockedTotal}} queries blocked since KyDNS started.</p>
</div>

{{if .StaleAny}}
<div class="card">
  <p class="error">A list below has never loaded or failed its last refresh.
     Its last known-good copy is still in force; nothing has stopped working.</p>
</div>
{{end}}

<div class="card">
  <h3>Lists</h3>
  <table class="grid">
    <tr><th>Name</th><th>Source</th><th>Format</th><th>Entries</th><th>Last update</th><th>State</th><th></th></tr>
    {{range .Lists}}
    <tr>
      <td>{{.Name}}{{if .Builtin}} <span class="badge accent">built-in</span>{{end}}
          {{if .Description}}<br><span class="muted">{{.Description}}</span>{{end}}</td>
      <td><span class="muted">{{.URL}}</span></td>
      <td>{{.Format}}</td>
      <td>{{.Entries}}{{if .Skipped}} <span class="muted">({{.Skipped}} skipped)</span>{{end}}</td>
      <td>{{.LastOK}}<br><span class="muted">every {{.Interval}}</span></td>
      <td>
        {{if .Enabled}}<span class="badge accent">on</span>{{else}}<span class="badge">off</span>{{end}}
        {{if .NeverLoaded}}<br><span class="badge warn">never loaded</span>{{end}}
        {{if .Stale}}<br><span class="badge warn">stale</span><br><span class="muted">{{.LastError}}</span>{{end}}
      </td>
      <td>
        <form class="address-row" method="post" action="/blacklists/lists/toggle">
          <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
          <input type="hidden" name="id" value="{{.ID}}">
          <button type="submit">{{if .Enabled}}Disable{{else}}Enable{{end}}</button>
        </form>
        <form class="address-row" method="post" action="/blacklists/refresh">
          <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
          <input type="hidden" name="id" value="{{.ID}}">
          <button class="ghost" type="submit">Refresh</button>
        </form>
        {{if not .Builtin}}
        <form class="address-row" method="post" action="/blacklists/lists/delete">
          <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
          <input type="hidden" name="id" value="{{.ID}}">
          <button class="danger" type="submit">Remove</button>
        </form>
        {{end}}
      </td>
    </tr>
    {{else}}
    <tr><td colspan="7" class="muted">No lists yet.</td></tr>
    {{end}}
  </table>
</div>

<div class="card">
  <h3>Add a list</h3>
  <p class="muted">A list URL is a trust decision: KyDNS downloads and applies
     whatever it says. Only https sources are accepted, and no query names,
     client addresses, or identifying headers are ever sent to the host.</p>
  <form class="stack" method="post" action="/blacklists/lists/new">
    <input type="hidden" name="csrf_token" value="{{.CSRF}}">
    <label for="bl-name">Name</label>
    <input id="bl-name" name="name" type="text" placeholder="my-list">
    <label for="bl-url">Source URL</label>
    <input id="bl-url" name="url" type="text" placeholder="https://lists.example/hosts">
    <label for="bl-format">Format</label>
    <select id="bl-format" name="format">
      <option value="domains">domains — one name per line</option>
      <option value="hosts">hosts — 0.0.0.0 name</option>
      <option value="adblock">adblock — ||name^</option>
    </select>
    <label for="bl-interval">Refresh every (seconds)</label>
    <input id="bl-interval" name="interval" type="text" value="86400">
    <button type="submit">Add list</button>
  </form>
</div>

<div class="card">
  <h3>One-off rules</h3>
  <p class="muted">A deny rule always wins over an allow rule. Both cover the
     name and its subdomains. Neither can affect a name KyDNS answers for
     itself — local services and records are decided before any of this.</p>
  <table class="grid">
    <tr><th>Kind</th><th>Domain</th><th></th></tr>
    {{range .Deny}}
    <tr><td><span class="badge down">deny</span></td><td>{{.Domain}}</td>
      <td><form method="post" action="/blacklists/rules/delete">
        <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
        <input type="hidden" name="id" value="{{.ID}}">
        <button class="danger" type="submit">Remove</button>
      </form></td></tr>
    {{end}}
    {{range .Allow}}
    <tr><td><span class="badge accent">allow</span></td><td>{{.Domain}}</td>
      <td><form method="post" action="/blacklists/rules/delete">
        <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
        <input type="hidden" name="id" value="{{.ID}}">
        <button class="danger" type="submit">Remove</button>
      </form></td></tr>
    {{end}}
  </table>
  <form class="stack" method="post" action="/blacklists/rules/new">
    <input type="hidden" name="csrf_token" value="{{.CSRF}}">
    <label for="rule-domain">Domain</label>
    <input id="rule-domain" name="domain" type="text" placeholder="ads.example">
    <label for="rule-kind">Rule</label>
    <select id="rule-kind" name="kind">
      <option value="deny">Deny — always block</option>
      <option value="allow">Allow — never block</option>
    </select>
    <button type="submit">Add rule</button>
  </form>
</div>

<div class="card">
  <h3>Test a name</h3>
  {{with .Result}}
    {{if .Blocked}}
      <p class="error">{{.Name}} is blocked by <strong>{{.Policy}}</strong>.</p>
    {{else}}
      <p>{{.Name}} is allowed ({{.Policy}}).</p>
    {{end}}
  {{end}}
  <form class="stack" method="post" action="/blacklists/test">
    <input type="hidden" name="csrf_token" value="{{.CSRF}}">
    <label for="test-name">Domain</label>
    <input id="test-name" name="name" type="text" placeholder="ads.example">
    <button type="submit">Test</button>
  </form>
</div>

{{end}}
{{end}}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./internal/web/... -v`
Expected: PASS, including every pre-existing web test.

- [ ] **Step 8: Verify the whole tree**

Run: `go build ./... && go vet ./... && gofmt -l . && CGO_ENABLED=0 go test ./...`
Expected: clean. `gofmt -l .` in particular will flag the `blacklistRow` field alignment — run `gofmt -w internal/web/blacklists.go`.

- [ ] **Step 9: Commit**

```bash
git add internal/web/
git commit -m "feat(web): Blacklists tab with lists, rules, refresh and a test box"
```

---

## Task 13: Wire it into the process, document it, and prove the end-to-end guarantees

**Files:**
- Modify: `internal/app/serve.go:33-217` — build the policy, seed built-ins, run the refresher, pass it to the DNS server, the API and the web UI
- Create: `internal/app/blacklist_test.go`
- Modify: `README.md`, `DESGINE.md`, `LOGGING.md`, `SECURITY.md`, `AGENTS.md`

**Interfaces:**
- Consumes: everything from Tasks 1–12.
- Produces: no new exported API. The process gains a live policy.

- [ ] **Step 1: Write the failing integration test**

Create `internal/app/blacklist_test.go`:

```go
package app

import (
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/policy"
	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)

// buildPolicy mirrors the wiring in Serve, so the test proves the shape the
// process actually runs rather than a parallel invention.
func buildPolicy(t *testing.T, st *store.Store) *policy.Service {
	t.Helper()
	h := policy.NewHolder(func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		set, err := st.BlacklistSettings()
		if err != nil {
			return set, nil, nil, err
		}
		lists, err := st.BlacklistLists()
		if err != nil {
			return set, nil, nil, err
		}
		rules, err := st.BlacklistRules()
		return set, lists, rules, err
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	return policy.NewService(st, h, policy.NewRefresher(st, policy.NewFetcher(0), h, nil))
}

// TestLocalRecordAndAllowRuleBothWin is the spec's required integration check:
// a name a list blocks is served locally when it is a KyDNS service, and an
// allow exception overrides the list for a public name.
func TestLocalRecordAndAllowRuleBothWin(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// A local service whose name a public list also carries.
	if _, err := st.PutService(store.Service{
		Name: "kypost", Addresses: []store.Address{{Address: "192.168.1.20"}},
	}); err != nil {
		t.Fatal(err)
	}
	// A list that blocks the local name, an unrelated name, and an excepted one.
	id, err := st.PutBlacklistList(store.BlacklistList{
		Name: "l1", URL: "https://lists.example/x", Format: policy.FormatDomains,
		Enabled: true, IntervalSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetBlacklistSnapshot(id,
		[]string{"ads.example", "kypost.home.arpa", "shared.example"}, 0, "", "", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutBlacklistRule(store.BlacklistRule{Kind: "allow", Domain: "shared.example"}); err != nil {
		t.Fatal(err)
	}

	pol := buildPolicy(t, st)
	if err := pol.SetSettings(true, 60); err != nil {
		t.Fatal(err)
	}

	zh := zone.NewHolder(func() (zone.Input, error) {
		svcs, err := st.Services()
		if err != nil {
			return zone.Input{}, err
		}
		return zone.Input{Zone: "home.arpa.", Services: svcs}, nil
	}, nil)
	if err := zh.Rebuild(); err != nil {
		t.Fatal(err)
	}

	// The service layer's Test is the same decision the DNS path uses.
	if d, err := pol.Test("ads.example"); err != nil || !d.Blocked {
		t.Errorf("ads.example = %+v %v, want blocked", d, err)
	}
	if d, err := pol.Test("shared.example"); err != nil || d.Blocked {
		t.Errorf("shared.example = %+v %v, want the allow rule to win", d, err)
	}

	// The local name is answered authoritatively, so the policy is never asked.
	auth := &dnsserver.Authoritative{Zone: "home.arpa.", TTL: 60}
	q := dns.Question{Name: "kypost.home.arpa.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	m := auth.Answer(zh.Current(), "", q)
	if m == nil || m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("local answer = %v, want the service address despite the list", m)
	}
	if a, ok := m.Answer[0].(*dns.A); !ok || a.A.String() != "192.168.1.20" {
		t.Errorf("local answer = %v, want 192.168.1.20", m.Answer[0])
	}
}
```

The imports for this file are exactly:

```go
import (
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/policy"
	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/app/ -run TestLocalRecord`
Expected: FAIL with "undefined: policy" until Tasks 1–8 are merged. This test exercises the policy service and the authoritative lookup directly, so it passes once those tasks are in place — the wiring in Step 3 is what puts the same shape into the running process.

- [ ] **Step 3: Wire the policy into `Serve`**

In `internal/app/serve.go`, after the `reg := registry.New(...)` block:

```go
	// Filtering is on by default. Built-ins seed once; an operator's later
	// edits to them survive every upgrade.
	if err := policy.SeedBuiltins(st); err != nil {
		return err
	}
	policyHolder := policy.NewHolder(func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		set, err := st.BlacklistSettings()
		if err != nil {
			return set, nil, nil, err
		}
		lists, err := st.BlacklistLists()
		if err != nil {
			return set, nil, nil, err
		}
		rules, err := st.BlacklistRules()
		return set, lists, rules, err
	})
	if err := policyHolder.Rebuild(); err != nil {
		return fmt.Errorf("initial blacklist policy: %w", err)
	}
	refresher := policy.NewRefresher(st, policy.NewFetcher(30*time.Second), policyHolder, logger)
	policySvc := policy.NewService(st, policyHolder, refresher)
```

with `"github.com/yoshiofthewire/kydns-server/internal/policy"` imported.

Pass the holder to the DNS server, in the `dnsserver.New(dnsserver.Options{...})` literal:

```go
		Policy:      policyHolder,
```

Attach the service to the API:

```go
	api := adminapi.NewAPI(reg, acl, cache).WithProviders(leaseFn, checker.Statuses).WithPolicy(policySvc)
```

Add it to the web options, next to `Cache:`:

```go
		Policy:         policySvc,
```

Start the refresher alongside the other background loops:

```go
	go refresher.Run(ctx)
```

And extend the startup line:

```go
	set, err := policySvc.Settings()
	if err != nil {
		return err
	}
	logger.Info("kydns started",
		"dns", cfg.DNS.Listen, "admin", cfg.Admin.Listen, "zone", cfg.PrivateFQDN(),
		"filtering", onOffLabel(set.Enabled))
```

with, at the bottom of `serve.go`:

```go
func onOffLabel(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
```

- [ ] **Step 4: Verify the whole tree**

Run: `go build ./... && go vet ./... && gofmt -l . && CGO_ENABLED=0 go test ./...`
Expected: clean, every test passing.

- [ ] **Step 5: Smoke-test the running server**

Run:

```bash
CGO_ENABLED=0 go build -o bin/kydns ./cmd/kydns
```

Then start it against a scratch config and confirm from the log line that `filtering=on`, that `blacklist list refreshed` appears within about 90 seconds, and that `kydns blacklist test <a name from the list>` reports it blocked. Stop the server afterwards.

- [ ] **Step 6: Update the documentation**

`README.md` — under the blacklist bullet at line 42, add a short section describing the Blacklists tab: the global toggle, built-in and custom lists, the three formats, the deny-beats-allow precedence, the label-boundary rule (`ads.example` matches its subdomains, not `badads.example`), that blocked names return local NXDOMAIN and never reach an upstream, and that a local service or record can never be blocked. Repeat the scope limit already at line 332: domain filtering only, not traffic inspection, parental control, or a malware guarantee. Name the built-in source and its license.

`DESGINE.md` — at the "Policy engine" bullet (line 30), record where the policy sits in the pipeline: ACL and authoritative lookup, then policy for non-authoritative names, then local NXDOMAIN or the existing cache and forwarder. Under "Local data", add list definitions, refresh metadata, one-off rules, and the last known-good normalized snapshots, and note that list contents are data, not executable configuration. Note that the export omits list bodies.

`LOGGING.md` — record the new events (`blacklist list refreshed`, `blacklist list refresh failed…`, `blacklist list unchanged`, settings and rule changes) and the query log's `policy` field with its values `local`, `allow`, `deny`, a list name, or `forwarded`. State that downloaded content, list URLs with credentials, client IPs and query names are never logged by default, and that counters expose blocked totals and per-list counts, never client identity.

`SECURITY.md` — at lines 19 and 35, confirm what shipped: HTTPS-only with verification, redirects that must stay HTTPS, a 32 MB body ceiling, a parse entry ceiling, no code execution, and the fixed `User-Agent: kydns` with no other identifying headers. Note that only authenticated administrators can change policy.

`AGENTS.md` — add `internal/policy` to the Child DOX Index with a one-line responsibility, and add this plan's spec to the list of aligned documents.

- [ ] **Step 7: Re-read the spec against the implementation**

Open `docs/superpowers/specs/2026-08-12-kydns-blacklists.md` and walk its "Verification" list, confirming each item has a passing test:

normalization and suffix boundaries (Task 1); precedence (Task 4); all three formats and malformed-line counts (Task 2); transactional refresh and stale snapshot retention (Task 7); no upstream request for blocked names (Task 5); API authorization (Task 9); export omission of list bodies and credentials (Task 10); import validation (Task 10); cache behavior — the block TTL on the synthesized SOA (Task 5); blocked counters (Task 4); and the allow-exception plus local-record integration test (Task 13).

- [ ] **Step 8: Commit**

```bash
git add internal/app/ README.md DESGINE.md LOGGING.md SECURITY.md AGENTS.md
git commit -m "feat: wire blacklist filtering into the server and document it"
```

---

## Deferred, deliberately

These are named in the spec or implied by it and are **not** in this plan:

- **Per-view policy.** The spec says filtering does not vary by client view in this version.
- **Background catch-up on resume beyond the foreground tick.** `Refresher.Run` refreshes due lists immediately on start and every 90 seconds; a laptop resuming from sleep catches up on the next tick.
- **Regex or wildcard rules.** Suffix matching only, which is what the spec specifies.
- **Blocked-response modes other than NXDOMAIN** (0.0.0.0 sinkholing, custom addresses).
- **A second built-in list.** The manifest is versioned so a release can add one without touching policy code.
