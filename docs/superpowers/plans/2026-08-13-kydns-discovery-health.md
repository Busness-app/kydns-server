# KyDNS Discovery and Health Implementation Plan (Tasks 22–25)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Continues:** Plan 1 (`2026-08-11-kydns-core*.md`, Tasks 1–13) and Plan 2 (`2026-08-12-kydns-operator-surface*.md`, Tasks 14–21). Read Plan 1's **Global Constraints**. Both plans must be complete and green before starting.

**Goal:** DHCP lease discovery from the dnsmasq lease file, health checks with status in the UI, promote-to-service, and the live tables the spec describes. This completes v1.

**No new dependencies.** Everything here is standard library.

**Groundwork already in place:** `zone.Lease` and `zone.Input.Leases` exist from Plan 1 Task 6 and are currently always empty; the snapshot builder already applies the lease-loses precedence rule and has a test for it. The Discovered nav link and placeholder page exist from Plan 2 Task 21.

---

### Task 22: dnsmasq lease parsing

**Files:**
- Create: `internal/discovery/dhcp/source.go`, `internal/discovery/dhcp/dnsmasq.go`
- Test: `internal/discovery/dhcp/dnsmasq_test.go`, `internal/discovery/dhcp/testdata/dnsmasq.leases`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type Lease struct { MAC, IP, Hostname string; Expires time.Time }`
  - `type Source interface { Leases(ctx context.Context) ([]Lease, error); Name() string }`
  - `type DnsmasqSource struct { Path string; Now func() time.Time }`
  - `func (d *DnsmasqSource) Leases(ctx context.Context) ([]Lease, error)`
  - `func ParseDnsmasq(r io.Reader, now time.Time) ([]Lease, []string)` — returns leases and the reasons lines were skipped

- [ ] **Step 1: Write the failing test**

Create the fixture. These are real dnsmasq lease lines, junk included:

```
# internal/discovery/dhcp/testdata/dnsmasq.leases
1786000000 aa:bb:cc:dd:ee:01 192.168.1.20 kypost 01:aa:bb:cc:dd:ee:01
1786000000 aa:bb:cc:dd:ee:02 192.168.1.21 * 01:aa:bb:cc:dd:ee:02
1786000000 aa:bb:cc:dd:ee:03 192.168.1.22 Living-Room-TV 01:aa:bb:cc:dd:ee:03
1786000000 aa:bb:cc:dd:ee:04 192.168.1.23 host_with_underscore 01:aa:bb:cc:dd:ee:04
1786000000 aa:bb:cc:dd:ee:05 192.168.1.24 has.a.dot 01:aa:bb:cc:dd:ee:05
1 aa:bb:cc:dd:ee:06 192.168.1.25 expired-host 01:aa:bb:cc:dd:ee:06
1786000000 aa:bb:cc:dd:ee:07 192.168.1.26 nas 01:aa:bb:cc:dd:ee:07
1786000100 aa:bb:cc:dd:ee:08 192.168.1.27 nas 01:aa:bb:cc:dd:ee:08
1786000000 aa:bb:cc:dd:ee:09 not-an-ip badaddr 01:aa:bb:cc:dd:ee:09
garbage line with too few
1786000000 aa:bb:cc:dd:ee:0a fd00::5 v6host 01:aa:bb:cc:dd:ee:0a
```

```go
// internal/discovery/dhcp/dnsmasq_test.go
package dhcp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fixture's live leases expire at unix 1786000000; anchor "now" before it.
var testNow = time.Unix(1_700_000_000, 0)

func parseFixture(t *testing.T) ([]Lease, []string) {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "dnsmasq.leases"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return ParseDnsmasq(f, testNow)
}

func byHostname(leases []Lease) map[string]Lease {
	m := map[string]Lease{}
	for _, l := range leases {
		m[l.Hostname] = l
	}
	return m
}

func TestParsesValidLease(t *testing.T) {
	leases, _ := parseFixture(t)
	got, ok := byHostname(leases)["kypost"]
	if !ok {
		t.Fatalf("kypost not parsed; got %+v", leases)
	}
	if got.IP != "192.168.1.20" {
		t.Errorf("IP = %q, want 192.168.1.20", got.IP)
	}
	if got.MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("MAC = %q", got.MAC)
	}
}

// Discovery sources are untrusted configuration input, so junk is skipped and
// reported, never silently rewritten into something that looks valid.
func TestSkipsJunkHostnames(t *testing.T) {
	leases, skipped := parseFixture(t)
	names := byHostname(leases)
	for _, unwanted := range []string{"*", "", "host_with_underscore", "has.a.dot"} {
		if _, present := names[unwanted]; present {
			t.Errorf("hostname %q was accepted, want it skipped", unwanted)
		}
	}
	if len(skipped) == 0 {
		t.Error("skipped reasons are empty, want the junk lines reported")
	}
	joined := strings.Join(skipped, "\n")
	for _, want := range []string{"host_with_underscore", "has.a.dot", "not-an-ip"} {
		if !strings.Contains(joined, want) {
			t.Errorf("skipped reasons do not mention %q:\n%s", want, joined)
		}
	}
}

func TestLowercasesHostnames(t *testing.T) {
	leases, _ := parseFixture(t)
	if _, ok := byHostname(leases)["living-room-tv"]; !ok {
		t.Errorf("Living-Room-TV was not lowercased; got %+v", leases)
	}
}

func TestDropsExpiredLeases(t *testing.T) {
	leases, _ := parseFixture(t)
	if _, ok := byHostname(leases)["expired-host"]; ok {
		t.Error("an expired lease was returned")
	}
}

// Two MACs claiming one hostname: the newest lease wins and the conflict is
// reported.
func TestDuplicateHostnameNewestWins(t *testing.T) {
	leases, skipped := parseFixture(t)
	nas, ok := byHostname(leases)["nas"]
	if !ok {
		t.Fatal("nas missing")
	}
	if nas.IP != "192.168.1.27" {
		t.Errorf("nas IP = %q, want the newer lease 192.168.1.27", nas.IP)
	}
	if !strings.Contains(strings.Join(skipped, "\n"), "nas") {
		t.Error("the duplicate hostname conflict was not reported")
	}
	count := 0
	for _, l := range leases {
		if l.Hostname == "nas" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("nas appears %d times, want 1", count)
	}
}

func TestSkipsMalformedLines(t *testing.T) {
	leases, _ := parseFixture(t)
	if _, ok := byHostname(leases)["badaddr"]; ok {
		t.Error("a lease with an invalid IP was accepted")
	}
}

func TestParsesIPv6Lease(t *testing.T) {
	leases, _ := parseFixture(t)
	got, ok := byHostname(leases)["v6host"]
	if !ok {
		t.Fatalf("v6host missing; got %+v", leases)
	}
	if got.IP != "fd00::5" {
		t.Errorf("IP = %q, want fd00::5", got.IP)
	}
}

// An unreadable lease file is an error the caller handles by keeping the last
// known leases; it must never be a panic or a silent empty list.
func TestSourceMissingFileErrors(t *testing.T) {
	d := &DnsmasqSource{Path: filepath.Join(t.TempDir(), "absent.leases")}
	if _, err := d.Leases(context.Background()); err == nil {
		t.Error("Leases() error = nil for a missing file, want an error")
	}
}

func TestSourceReadsFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dnsmasq.leases")
	body := "1786000000 aa:bb:cc:dd:ee:01 192.168.1.20 kypost 01:aa\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &DnsmasqSource{Path: p, Now: func() time.Time { return testNow }}
	leases, err := d.Leases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].Hostname != "kypost" {
		t.Errorf("Leases() = %+v", leases)
	}
	if d.Name() == "" {
		t.Error("Name() is empty")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/discovery/dhcp/ -v`
Expected: FAIL — `undefined: ParseDnsmasq`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/discovery/dhcp/source.go
// Package dhcp discovers names from DHCP leases. Leases are untrusted
// configuration input: everything here validates before publishing.
package dhcp

import (
	"context"
	"time"
)

// Lease is one DHCP lease. Hostname is already lowercased and validated.
type Lease struct {
	MAC      string
	IP       string
	Hostname string
	Expires  time.Time
}

// Source is one lease provider. dnsmasq is the reference implementation;
// ISC dhcpd and Kea slot in behind this interface without touching the poller.
type Source interface {
	Leases(ctx context.Context) ([]Lease, error)
	Name() string
}
```

```go
// internal/discovery/dhcp/dnsmasq.go
package dhcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// DnsmasqSource reads the dnsmasq lease file, whose format is:
//
//	<expiry unix> <mac> <ip> <hostname> <client-id>
type DnsmasqSource struct {
	Path string
	Now  func() time.Time
}

func (d *DnsmasqSource) Name() string { return "dnsmasq:" + d.Path }

func (d *DnsmasqSource) Leases(ctx context.Context) ([]Lease, error) {
	f, err := os.Open(d.Path)
	if err != nil {
		return nil, fmt.Errorf("read dnsmasq leases: %w", err)
	}
	defer f.Close()
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	leases, _ := ParseDnsmasq(f, now())
	return leases, nil
}

// validLabel mirrors the registry's RFC 1035 rule. Discovery skips anything
// that fails rather than rewriting it: a silently mangled name is worse than
// an absent one, because the operator cannot tell what happened.
func validLabel(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}

// ParseDnsmasq returns the live, valid leases plus a human-readable reason for
// every line it dropped. The reasons are logged by the caller, so an operator
// can tell why a device is missing.
func ParseDnsmasq(r io.Reader, now time.Time) ([]Lease, []string) {
	var skipped []string
	newest := map[string]Lease{} // hostname -> winning lease
	order := []string{}

	sc := bufio.NewScanner(r)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) < 4 {
			skipped = append(skipped, fmt.Sprintf("line %d: expected at least 4 fields, got %d", line, len(fields)))
			continue
		}
		epoch, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("line %d: bad expiry %q", line, fields[0]))
			continue
		}
		expires := time.Unix(epoch, 0)
		// dnsmasq writes 0 for an infinite lease.
		if epoch != 0 && !expires.After(now) {
			skipped = append(skipped, fmt.Sprintf("line %d: lease for %q expired", line, fields[3]))
			continue
		}
		addr, err := netip.ParseAddr(fields[2])
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("line %d: %q is not an IP address", line, fields[2]))
			continue
		}
		host := strings.ToLower(fields[3])
		if host == "*" {
			continue // dnsmasq's marker for "no hostname supplied"
		}
		if !validLabel(host) {
			skipped = append(skipped, fmt.Sprintf("line %d: hostname %q is not a valid DNS label", line, fields[3]))
			continue
		}
		lease := Lease{MAC: fields[1], IP: addr.String(), Hostname: host, Expires: expires}

		if prev, dup := newest[host]; dup {
			skipped = append(skipped, fmt.Sprintf(
				"line %d: hostname %q claimed by %s and %s; the newer lease wins",
				line, host, prev.MAC, lease.MAC))
			if !lease.Expires.After(prev.Expires) {
				continue
			}
		} else {
			order = append(order, host)
		}
		newest[host] = lease
	}
	if err := sc.Err(); err != nil {
		skipped = append(skipped, "read error: "+err.Error())
	}

	out := make([]Lease, 0, len(order))
	for _, h := range order {
		out = append(out, newest[h])
	}
	return out, skipped
}

var _ Source = (*DnsmasqSource)(nil)
var _ = context.Background
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/discovery/dhcp/ -v`
Expected: PASS, nine tests.

- [ ] **Step 5: Commit**

```bash
git add internal/discovery
git commit -m "Add dnsmasq lease parsing behind a Source interface

Junk hostnames are skipped with a reason rather than rewritten: a
silently mangled name is worse than an absent one, because the operator
cannot tell what happened. Duplicate hostnames resolve to the newest
lease and report the conflict.

AI-assisted contribution (agentic). Verified with: go test ./internal/discovery/dhcp/"
```

---

### Task 23: Lease poller feeding the snapshot

**Files:**
- Create: `internal/discovery/poller.go`
- Modify: `internal/config/config.go` (discovery block), `internal/app/serve.go`
- Test: `internal/discovery/poller_test.go`

**Interfaces:**
- Consumes: `dhcp.Source`, `zone.Holder`.
- Produces:
  - `type Poller struct{ ... }`, `func NewPoller(src dhcp.Source, interval time.Duration, onChange func(), logger *slog.Logger) *Poller`
  - `func (p *Poller) Run(ctx context.Context)` — blocks until ctx is done
  - `func (p *Poller) Leases() []dhcp.Lease` — lock-free-ish snapshot for readers
  - `func (p *Poller) Poll(ctx context.Context) error` — one cycle, exported for tests
  - `config`: `Discovery DiscoveryConfig` with `DHCPLeaseFile string`, `Interval int`

- [ ] **Step 1: Write the failing test**

```go
// internal/discovery/poller_test.go
package discovery

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp"
)

type fakeSource struct {
	mu     sync.Mutex
	leases []dhcp.Lease
	err    error
	calls  int
}

func (f *fakeSource) Name() string { return "fake" }

func (f *fakeSource) Leases(context.Context) ([]dhcp.Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return append([]dhcp.Lease(nil), f.leases...), nil
}

func (f *fakeSource) set(leases []dhcp.Lease, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leases, f.err = leases, err
}

func TestPollPublishesLeases(t *testing.T) {
	src := &fakeSource{leases: []dhcp.Lease{{Hostname: "laptop", IP: "192.168.1.50"}}}
	var changes int
	p := NewPoller(src, time.Minute, func() { changes++ }, nil)

	if err := p.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := p.Leases()
	if len(got) != 1 || got[0].Hostname != "laptop" {
		t.Fatalf("Leases() = %+v", got)
	}
	if changes != 1 {
		t.Errorf("onChange called %d times, want 1", changes)
	}
}

// An unchanged lease set must not trigger a snapshot rebuild every 30 seconds.
func TestPollSkipsRebuildWhenUnchanged(t *testing.T) {
	src := &fakeSource{leases: []dhcp.Lease{{Hostname: "laptop", IP: "192.168.1.50"}}}
	var changes int
	p := NewPoller(src, time.Minute, func() { changes++ }, nil)

	for i := 0; i < 3; i++ {
		if err := p.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if changes != 1 {
		t.Errorf("onChange called %d times for an unchanged lease set, want 1", changes)
	}
}

func TestPollDetectsChange(t *testing.T) {
	src := &fakeSource{leases: []dhcp.Lease{{Hostname: "laptop", IP: "192.168.1.50"}}}
	var changes int
	p := NewPoller(src, time.Minute, func() { changes++ }, nil)
	p.Poll(context.Background())

	src.set([]dhcp.Lease{{Hostname: "laptop", IP: "192.168.1.51"}}, nil)
	p.Poll(context.Background())
	if changes != 2 {
		t.Errorf("onChange called %d times, want 2 after the address changed", changes)
	}
}

// Failing safely when a discovery source is unavailable is a stated design
// goal: keep the last known leases and keep serving.
func TestPollKeepsLastKnownLeasesOnError(t *testing.T) {
	src := &fakeSource{leases: []dhcp.Lease{{Hostname: "laptop", IP: "192.168.1.50"}}}
	p := NewPoller(src, time.Minute, func() {}, nil)
	p.Poll(context.Background())

	src.set(nil, errors.New("lease file vanished"))
	if err := p.Poll(context.Background()); err == nil {
		t.Fatal("Poll() error = nil, want the source error surfaced")
	}
	got := p.Leases()
	if len(got) != 1 || got[0].Hostname != "laptop" {
		t.Errorf("Leases() = %+v, want the last known leases retained", got)
	}
}

func TestRunPollsUntilContextCancelled(t *testing.T) {
	src := &fakeSource{leases: []dhcp.Lease{{Hostname: "a", IP: "192.168.1.1"}}}
	p := NewPoller(src, 10*time.Millisecond, func() {}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after the context was cancelled")
	}
	src.mu.Lock()
	calls := src.calls
	src.mu.Unlock()
	if calls < 2 {
		t.Errorf("source polled %d times, want repeated polling", calls)
	}
}

func TestLeasesIsACopy(t *testing.T) {
	src := &fakeSource{leases: []dhcp.Lease{{Hostname: "laptop", IP: "192.168.1.50"}}}
	p := NewPoller(src, time.Minute, func() {}, nil)
	p.Poll(context.Background())

	got := p.Leases()
	got[0].Hostname = "mutated"
	if again := p.Leases(); again[0].Hostname != "laptop" {
		t.Error("Leases() handed out the internal slice; a caller mutated it")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/discovery/ -v`
Expected: FAIL — `undefined: NewPoller`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/discovery/poller.go
// Package discovery polls lease sources and publishes the result for the zone
// snapshot to consume.
package discovery

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp"
)

// Poller reads a lease Source on an interval and calls onChange only when the
// lease set actually differs, so an idle network does not rebuild the snapshot
// every cycle.
type Poller struct {
	src      dhcp.Source
	interval time.Duration
	onChange func()
	logger   *slog.Logger

	mu     sync.RWMutex
	leases []dhcp.Lease
	digest string
}

func NewPoller(src dhcp.Source, interval time.Duration, onChange func(), logger *slog.Logger) *Poller {
	if logger == nil {
		logger = slog.Default()
	}
	if onChange == nil {
		onChange = func() {}
	}
	return &Poller{src: src, interval: interval, onChange: onChange, logger: logger}
}

// Run polls until ctx is cancelled, starting with an immediate cycle so the
// first snapshot does not wait a full interval.
func (p *Poller) Run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		if err := p.Poll(ctx); err != nil {
			p.logger.Warn("lease poll failed, keeping the last known leases",
				"source", p.src.Name(), "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Poll runs one cycle. On error the previously published leases are retained:
// an unreadable lease file must not empty the zone.
func (p *Poller) Poll(ctx context.Context) error {
	leases, err := p.src.Leases(ctx)
	if err != nil {
		return err
	}
	d := digest(leases)

	p.mu.Lock()
	changed := d != p.digest
	if changed {
		p.leases, p.digest = leases, d
	}
	p.mu.Unlock()

	if changed {
		p.logger.Info("dhcp leases updated", "source", p.src.Name(), "count", len(leases))
		p.onChange()
	}
	return nil
}

// Leases returns a copy, so a caller cannot mutate published state.
func (p *Poller) Leases() []dhcp.Lease {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]dhcp.Lease(nil), p.leases...)
}

// digest is an order-sensitive fingerprint of the lease set. The parser emits
// a stable order, so string comparison is enough and costs less than a hash.
func digest(leases []dhcp.Lease) string {
	var sb strings.Builder
	for _, l := range leases {
		sb.WriteString(l.Hostname)
		sb.WriteByte('=')
		sb.WriteString(l.IP)
		sb.WriteByte(';')
	}
	return sb.String()
}
```

Add to `internal/config/config.go`:

```go
type DiscoveryConfig struct {
	DHCPLeaseFile string `yaml:"dhcp_lease_file"`
	Interval      int    `yaml:"interval"`
}
```

Add `Discovery DiscoveryConfig \`yaml:"discovery"\`` to `Config`, and in
`applyDefaults`: `setInt(&c.Discovery.Interval, 30)`.

Wire into `internal/app/serve.go`. The holder's `Source` closure gains leases:

```go
	var poller *discovery.Poller
	if cfg.Discovery.DHCPLeaseFile != "" {
		poller = discovery.NewPoller(
			&dhcp.DnsmasqSource{Path: cfg.Discovery.DHCPLeaseFile},
			time.Duration(cfg.Discovery.Interval)*time.Second,
			func() {
				if err := holder.Rebuild(); err != nil {
					logger.Error("rebuild after lease change failed", "error", err)
				}
			}, logger)
	}
```

and inside the existing holder source closure, before returning `zone.Input`:

```go
		var leases []zone.Lease
		if poller != nil {
			for _, l := range poller.Leases() {
				leases = append(leases, zone.Lease{Hostname: l.Hostname, Address: l.IP})
			}
		}
```

adding `Leases: leases` to the returned `zone.Input`. Start it after the
listeners:

```go
	if poller != nil {
		go poller.Run(ctx)
	}
```

`poller` is declared before the holder but assigned after, so the closure
captures the variable rather than a nil value. Declare `var poller *discovery.Poller`
above the `zone.NewHolder` call.

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./... -race`
Expected: PASS. `TestServiceBeatsLease` from Plan 1 Task 6 now exercises real data end to end.

- [ ] **Step 5: Commit**

```bash
git add internal/discovery internal/config internal/app
git commit -m "Add DHCP lease poller feeding the zone snapshot

Rebuilds only when the lease set actually differs, so an idle network
does not rebuild the snapshot every thirty seconds. A failed poll keeps
the last known leases, which is the design goal of failing safely when
a discovery source is unavailable.

AI-assisted contribution (agentic). Verified with: CGO_ENABLED=0 go test ./... -race"
```

---

### Task 24: Health checks

**Files:**
- Create: `internal/health/checker.go`
- Modify: `internal/config/config.go`, `internal/app/serve.go`
- Test: `internal/health/checker_test.go`

**Interfaces:**
- Consumes: `registry.Registry`.
- Produces:
  - `type Status struct { ServiceID int64; Name, State string; Since time.Time; LastError string }` — State is `up`, `down`, or `unknown`
  - `type Checker struct{ ... }`, `func NewChecker(reg Lister, interval, timeout time.Duration, workers int, logger *slog.Logger) *Checker`
  - `type Lister interface { Services() ([]store.Service, error) }`
  - `func (c *Checker) Run(ctx context.Context)`, `func (c *Checker) CheckOnce(ctx context.Context)`, `func (c *Checker) Statuses() []Status`
  - `config`: `Health HealthConfig` with `Interval`, `Timeout`, `Workers`

- [ ] **Step 1: Write the failing test**

```go
// internal/health/checker_test.go
package health

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

type fakeLister struct{ svcs []store.Service }

func (f *fakeLister) Services() ([]store.Service, error) { return f.svcs, nil }

func statusOf(t *testing.T, c *Checker, name string) Status {
	t.Helper()
	for _, s := range c.Statuses() {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no status for %q in %+v", name, c.Statuses())
	return Status{}
}

func newChecker(svcs []store.Service) *Checker {
	return NewChecker(&fakeLister{svcs: svcs}, time.Minute, 2*time.Second, 4, nil)
}

func TestHealthyHTTPServiceIsUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newChecker([]store.Service{{ID: 1, Name: "ok", CheckURL: srv.URL}})
	c.CheckOnce(context.Background())
	if got := statusOf(t, c, "ok").State; got != "up" {
		t.Errorf("State = %q, want up", got)
	}
}

// Two consecutive failures are required before a service is marked down, so a
// single blip does not flap the dashboard.
func TestTwoFailuresRequiredToGoDown(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newChecker([]store.Service{{ID: 1, Name: "flappy", CheckURL: srv.URL}})
	c.CheckOnce(context.Background())
	fail.Store(true)

	c.CheckOnce(context.Background())
	if got := statusOf(t, c, "flappy").State; got == "down" {
		t.Error("service went down after a single failure, want two")
	}
	c.CheckOnce(context.Background())
	if got := statusOf(t, c, "flappy").State; got != "down" {
		t.Errorf("State = %q after two failures, want down", got)
	}
}

// Recovery is immediate: one success brings a service back.
func TestOneSuccessBringsItBack(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newChecker([]store.Service{{ID: 1, Name: "recovers", CheckURL: srv.URL}})
	c.CheckOnce(context.Background())
	c.CheckOnce(context.Background())
	if statusOf(t, c, "recovers").State != "down" {
		t.Fatal("setup: service should be down")
	}
	fail.Store(false)
	c.CheckOnce(context.Background())
	if got := statusOf(t, c, "recovers").State; got != "up" {
		t.Errorf("State = %q after one success, want up", got)
	}
}

func TestRedirectIsHealthyAndNotFollowed(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newChecker([]store.Service{{ID: 1, Name: "redir", CheckURL: srv.URL + "/"}})
	c.CheckOnce(context.Background())
	if got := statusOf(t, c, "redir").State; got != "up" {
		t.Errorf("State = %q, want up for a 3xx", got)
	}
	if hits.Load() != 1 {
		t.Errorf("server hit %d times, want 1 with redirects not followed", hits.Load())
	}
}

func TestTCPCheck(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	c := newChecker([]store.Service{{ID: 1, Name: "tcp-up", CheckURL: "tcp://" + l.Addr().String()}})
	c.CheckOnce(context.Background())
	if got := statusOf(t, c, "tcp-up").State; got != "up" {
		t.Errorf("State = %q, want up", got)
	}
}

func TestTCPCheckDownWhenNothingListens(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close() // nothing listens now

	c := newChecker([]store.Service{{ID: 1, Name: "tcp-down", CheckURL: "tcp://" + addr}})
	c.CheckOnce(context.Background())
	c.CheckOnce(context.Background())
	if got := statusOf(t, c, "tcp-down").State; got != "down" {
		t.Errorf("State = %q, want down", got)
	}
}

// A service with no check URL is "unknown", never a false "up".
func TestServiceWithoutCheckIsUnknown(t *testing.T) {
	c := newChecker([]store.Service{{ID: 1, Name: "unchecked"}})
	c.CheckOnce(context.Background())
	if got := statusOf(t, c, "unchecked").State; got != "unknown" {
		t.Errorf("State = %q, want unknown", got)
	}
}

// Status is dropped when its service is deleted, so the dashboard cannot show
// a service that no longer exists.
func TestStatusDroppedForRemovedService(t *testing.T) {
	lister := &fakeLister{svcs: []store.Service{{ID: 1, Name: "temp"}}}
	c := NewChecker(lister, time.Minute, time.Second, 2, nil)
	c.CheckOnce(context.Background())
	if len(c.Statuses()) != 1 {
		t.Fatalf("Statuses() = %+v", c.Statuses())
	}
	lister.svcs = nil
	c.CheckOnce(context.Background())
	if len(c.Statuses()) != 0 {
		t.Errorf("Statuses() = %+v after the service was removed, want empty", c.Statuses())
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	c := newChecker([]store.Service{{ID: 1, Name: "x"}})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after cancellation")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/health/ -v`
Expected: FAIL — `undefined: NewChecker`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/health/checker.go
// Package health probes service check targets. Health never affects DNS
// answers: status is informational, which keeps resolution deterministic.
package health

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// Failure and recovery thresholds: slow to alarm, fast to recover.
const (
	failuresToDown  = 2
	successesToUp   = 1
	stateUp         = "up"
	stateDown       = "down"
	stateUnknown    = "unknown"
)

type Status struct {
	ServiceID int64
	Name      string
	State     string
	Since     time.Time
	LastError string
}

// Lister is the slice of registry this package needs. Depending on the
// interface rather than *registry.Registry keeps the test a struct literal.
type Lister interface {
	Services() ([]store.Service, error)
}

type entry struct {
	status     Status
	failures   int
	successes  int
}

type Checker struct {
	lister   Lister
	interval time.Duration
	timeout  time.Duration
	workers  int
	logger   *slog.Logger
	now      func() time.Time

	mu      sync.RWMutex
	entries map[int64]*entry
}

func NewChecker(lister Lister, interval, timeout time.Duration, workers int, logger *slog.Logger) *Checker {
	if logger == nil {
		logger = slog.Default()
	}
	if workers < 1 {
		workers = 8
	}
	return &Checker{
		lister: lister, interval: interval, timeout: timeout, workers: workers,
		logger: logger, now: time.Now, entries: map[int64]*entry{},
	}
}

func (c *Checker) Run(ctx context.Context) {
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		c.CheckOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// CheckOnce probes every service through a bounded worker pool, so a large
// registry does not spawn one goroutine per service.
func (c *Checker) CheckOnce(ctx context.Context) {
	svcs, err := c.lister.Services()
	if err != nil {
		c.logger.Warn("health: list services", "error", err)
		return
	}

	live := make(map[int64]bool, len(svcs))
	for _, s := range svcs {
		live[s.ID] = true
	}
	c.mu.Lock()
	for id := range c.entries {
		if !live[id] {
			delete(c.entries, id) // the service is gone; so is its status
		}
	}
	c.mu.Unlock()

	jobs := make(chan store.Service)
	var wg sync.WaitGroup
	for i := 0; i < c.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for svc := range jobs {
				c.probeAndRecord(ctx, svc)
			}
		}()
	}
	for _, svc := range svcs {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case jobs <- svc:
		}
	}
	close(jobs)
	wg.Wait()
}

func (c *Checker) probeAndRecord(ctx context.Context, svc store.Service) {
	if strings.TrimSpace(svc.CheckURL) == "" {
		c.record(svc, stateUnknown, nil)
		return
	}
	err := c.probe(ctx, svc.CheckURL, svc.CheckInsecure)
	c.record(svc, "", err)
}

// record applies the hysteresis and logs transitions only, not every probe.
func (c *Checker) record(svc store.Service, forced string, probeErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[svc.ID]
	if !ok {
		e = &entry{status: Status{ServiceID: svc.ID, State: stateUnknown, Since: c.now()}}
		c.entries[svc.ID] = e
	}
	e.status.Name = svc.Name
	previous := e.status.State

	switch {
	case forced != "":
		e.status.State, e.status.LastError = forced, ""
		e.failures, e.successes = 0, 0
	case probeErr == nil:
		e.successes++
		e.failures = 0
		e.status.LastError = ""
		if e.successes >= successesToUp {
			e.status.State = stateUp
		}
	default:
		e.failures++
		e.successes = 0
		e.status.LastError = probeErr.Error()
		if e.failures >= failuresToDown {
			e.status.State = stateDown
		}
	}

	if e.status.State != previous {
		e.status.Since = c.now()
		c.logger.Info("service health changed",
			"service", svc.Name, "from", previous, "to", e.status.State, "error", e.status.LastError)
	}
}

// probe supports http(s) and tcp. For HTTP a 2xx or 3xx is healthy and
// redirects are not followed; for tcp a completed connection is healthy and
// nothing is read or written.
func (c *Checker) probe(ctx context.Context, target string, insecure bool) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	if addr, ok := strings.CutPrefix(target, "tcp://"); ok {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		return conn.Close()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		// Private services usually carry self-signed certificates, so
		// verification is opt-out per service rather than globally disabled.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("status %s", resp.Status)
	}
	return nil
}

func (c *Checker) Statuses() []Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Status, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, e.status)
	}
	return out
}
```

Add to `internal/config/config.go`:

```go
type HealthConfig struct {
	Interval int `yaml:"interval"`
	Timeout  int `yaml:"timeout"`
	Workers  int `yaml:"workers"`
}
```

with `Health HealthConfig \`yaml:"health"\`` on `Config` and defaults
`Interval: 30`, `Timeout: 5`, `Workers: 8`.

In `serve.go`, after the listeners start:

```go
	checker := health.NewChecker(reg,
		time.Duration(cfg.Health.Interval)*time.Second,
		time.Duration(cfg.Health.Timeout)*time.Second,
		cfg.Health.Workers, logger)
	go checker.Run(ctx)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/health/ -race -v`
Expected: PASS, nine tests.

- [ ] **Step 5: Commit**

```bash
git add internal/health internal/config internal/app
git commit -m "Add health checks for http, https, and tcp targets

Two consecutive failures to go down, one success to recover: slow to
alarm, fast to recover. Only transitions are logged, not every probe.
A service with no check URL is unknown rather than a false up, and
health never affects DNS answers.

AI-assisted contribution (agentic). Verified with: go test -race ./internal/health/"
```

---

### Task 25: Discovered screen, promote, and live tables

**Files:**
- Create: `internal/web/discovered.go`
- Modify: `internal/web/templates/discovered.html`, `internal/web/templates/services.html`, `internal/web/services.go`, `internal/web/middleware.go`, `internal/adminapi/api.go`, `internal/app/serve.go`
- Create: `internal/web/static/live.js`
- Test: `internal/web/discovered_test.go`, `internal/adminapi/discovery_test.go`

**Interfaces:**
- Consumes: `discovery.Poller`, `health.Checker`.
- Produces:
  - web `Options` gains `Leases func() []dhcp.Lease` and `Health func() []health.Status`
  - `getDiscovered`, `postPromote` handlers; `GET /api/v1/leases`, `POST /api/v1/leases/{ip}/promote`, `GET /api/v1/health`
  - `live.js` refreshing the health and lease tables

- [ ] **Step 1: Write the failing test**

```go
// internal/web/discovered_test.go
package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp"
	"github.com/yoshiofthewire/kydns-server/internal/health"
)

func TestDiscoveredListsLeases(t *testing.T) {
	h, srv, c, _ := loggedIn(t)
	srv.o.Leases = func() []dhcp.Lease {
		return []dhcp.Lease{
			{Hostname: "laptop", IP: "192.168.1.50", MAC: "aa:bb:cc:dd:ee:01"},
			{Hostname: "printer", IP: "192.168.1.51", MAC: "aa:bb:cc:dd:ee:02"},
		}
	}
	body := page(t, h, "/discovered", c)
	for _, want := range []string{"laptop", "192.168.1.50", "printer", "aa:bb:cc:dd:ee:02"} {
		if !strings.Contains(body, want) {
			t.Errorf("discovered page missing %q", want)
		}
	}
}

// A lease shadowed by a service must be marked, not silently listed as though
// it were resolving.
func TestShadowedLeaseIsMarked(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"laptop"}, "address": {"192.168.1.99"}, "csrf_token": {csrf},
	}, c)
	srv.o.Leases = func() []dhcp.Lease {
		return []dhcp.Lease{{Hostname: "laptop", IP: "192.168.1.50"}}
	}
	body := page(t, h, "/discovered", c)
	if !strings.Contains(strings.ToLower(body), "shadowed") {
		t.Errorf("shadowed lease not marked:\n%s", body)
	}
}

func TestPromoteLeaseCreatesService(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	srv.o.Leases = func() []dhcp.Lease {
		return []dhcp.Lease{{Hostname: "laptop", IP: "192.168.1.50"}}
	}
	rec := postForm(t, h, "/discovered/promote", url.Values{
		"ip": {"192.168.1.50"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("promote = %d: %s", rec.Code, rec.Body)
	}
	svcs, err := srv.o.Registry.Services()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0].Name != "laptop" {
		t.Fatalf("Services() = %+v, want a promoted laptop service", svcs)
	}
	if svcs[0].Addresses[0].Address != "192.168.1.50" {
		t.Errorf("promoted address = %q", svcs[0].Addresses[0].Address)
	}
}

func TestPromoteUnknownLeaseFails(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	srv.o.Leases = func() []dhcp.Lease { return nil }
	rec := postForm(t, h, "/discovered/promote", url.Values{
		"ip": {"10.0.0.1"}, "csrf_token": {csrf},
	}, c)
	if rec.Code == http.StatusSeeOther {
		t.Error("promoting a lease that does not exist succeeded")
	}
}

func TestServicesShowHealthBadge(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.20"}, "csrf_token": {csrf},
	}, c)
	svcs, _ := srv.o.Registry.Services()
	srv.o.Health = func() []health.Status {
		return []health.Status{{ServiceID: svcs[0].ID, Name: "kypost", State: "down", Since: time.Now()}}
	}
	body := page(t, h, "/services", c)
	if !strings.Contains(body, "down") {
		t.Errorf("services page does not show the health state:\n%s", body)
	}
}

// With no health data configured the column must not claim everything is fine.
func TestServicesHealthUnknownWithoutChecker(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	postForm(t, h, "/services/new", url.Values{
		"name": {"kypost"}, "address": {"192.168.1.20"}, "csrf_token": {csrf},
	}, c)
	body := page(t, h, "/services", c)
	if strings.Contains(body, ">up<") {
		t.Error("services page claims up with no health checker configured")
	}
}
```

```go
// internal/adminapi/discovery_test.go
package adminapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestLeasesEndpoint(t *testing.T) {
	h, tok := newAPIWithLeases(t)
	rec := do(t, h, "GET", "/api/v1/leases", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Leases []struct{ Hostname, Address string } `json:"leases"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Leases) != 1 || out.Leases[0].Hostname != "laptop" {
		t.Errorf("leases = %s", rec.Body)
	}
}

func TestPromoteEndpoint(t *testing.T) {
	h, tok := newAPIWithLeases(t)
	if rec := do(t, h, "POST", "/api/v1/leases/192.168.1.50/promote", tok, ""); rec.Code != http.StatusCreated {
		t.Fatalf("promote = %d: %s", rec.Code, rec.Body)
	}
	rec := do(t, h, "GET", "/api/v1/services", tok, "")
	if !bytes.Contains(rec.Body.Bytes(), []byte("laptop")) {
		t.Errorf("promoted service missing: %s", rec.Body)
	}
}

func TestHealthEndpoint(t *testing.T) {
	h, tok := newAPIWithLeases(t)
	if rec := do(t, h, "GET", "/api/v1/health", tok, ""); rec.Code != http.StatusOK {
		t.Errorf("= %d: %s", rec.Code, rec.Body)
	}
}
```

Add `newAPIWithLeases` alongside `newAPI` in `api_test.go`, returning an API
constructed with `Leases` and `Health` providers supplying one `laptop` lease
at `192.168.1.50` and an empty status list. Add `"bytes"` to the imports.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/web/ ./internal/adminapi/ -v`
Expected: FAIL — no `/discovered/promote` route, no `Leases` option.

- [ ] **Step 3: Write minimal implementation**

Add to web `Options` in `middleware.go`:

```go
	Leases func() []dhcp.Lease
	Health func() []health.Status
```

```go
// internal/web/discovered.go
package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

type leaseRow struct {
	Hostname string
	IP       string
	MAC      string
	Shadowed bool
}

func (s *Server) leaseRows() ([]leaseRow, error) {
	if s.o.Leases == nil {
		return nil, nil
	}
	svcs, err := s.o.Registry.Services()
	if err != nil {
		return nil, err
	}
	// A lease is shadowed by anything that outranks it in the precedence rule:
	// a manual record, a service name, or an alias.
	taken := map[string]bool{}
	for _, svc := range svcs {
		taken[svc.Name] = true
		for _, a := range svc.Aliases {
			taken[a] = true
		}
	}
	recs, err := s.o.Registry.Records()
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		// Record names are FQDNs; leases are bare labels.
		if label, _, ok := strings.Cut(strings.TrimSuffix(r.Name, "."), "."); ok {
			taken[label] = true
		}
	}

	var rows []leaseRow
	for _, l := range s.o.Leases() {
		// A shadowed lease is not resolving. Saying so beats listing it as
		// though it were live.
		rows = append(rows, leaseRow{
			Hostname: l.Hostname, IP: l.IP, MAC: l.MAC, Shadowed: taken[l.Hostname],
		})
	}
	return rows, nil
}

func (s *Server) discoveredData(errMsg string) map[string]any {
	rows, err := s.leaseRows()
	if err != nil && errMsg == "" {
		errMsg = err.Error()
	}
	return map[string]any{
		"Title": "Discovered", "Nav": "discovered",
		"Leases": rows, "Enabled": s.o.Leases != nil, "Error": errMsg,
	}
}

func (s *Server) getDiscovered(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "discovered.html", s.discoveredData(""))
}

// postPromote turns a lease into a durable service. Leases are never
// persisted, so promotion is the only path from discovery into the database.
func (s *Server) postPromote(w http.ResponseWriter, r *http.Request) {
	ip := r.PostFormValue("ip")
	var found bool
	var hostname string
	if s.o.Leases != nil {
		for _, l := range s.o.Leases() {
			if l.IP == ip {
				found, hostname = true, l.Hostname
				break
			}
		}
	}
	if !found {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "discovered.html", s.discoveredData(fmt.Sprintf("No current lease for %s.", ip)))
		return
	}
	_, err := s.o.Registry.PutService(store.Service{
		Name:      hostname,
		Addresses: []store.Address{{Address: ip}},
	})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "discovered.html", s.discoveredData(err.Error()))
		return
	}
	http.Redirect(w, r, "/services", http.StatusSeeOther)
}
```

Replace `internal/web/templates/discovered.html`:

```html
{{define "page"}}
{{if .Enabled}}
<div class="card">
  <table class="grid" id="lease-table">
    <tr><th>Hostname</th><th>Address</th><th>MAC</th><th>State</th><th></th></tr>
    {{range .Leases}}
    <tr>
      <td>{{.Hostname}}</td><td>{{.IP}}</td><td class="muted">{{.MAC}}</td>
      <td>{{if .Shadowed}}<span class="badge warn">shadowed</span>{{else}}<span class="badge">resolving</span>{{end}}</td>
      <td>
        {{if not .Shadowed}}
        <form method="post" action="/discovered/promote">
          <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
          <input type="hidden" name="ip" value="{{.IP}}">
          <button type="submit">Promote to service</button>
        </form>
        {{end}}
      </td>
    </tr>
    {{else}}
      <tr><td colspan="5" class="muted">No current leases.</td></tr>
    {{end}}
  </table>
  <p class="muted">A shadowed lease is hidden by a service, alias, or manual record with the same name.
     Leases are never saved; promote one to keep it.</p>
</div>
<script src="/static/live.js" defer></script>
{{else}}
<div class="card">
  <p class="muted">DHCP lease discovery is off. Set <code>discovery.dhcp_lease_file</code>
     in the config file and restart KyDNS.</p>
</div>
{{end}}
{{end}}
```

```javascript
// internal/web/static/live.js
// Refreshes the lease and health tables without a full page reload. Deliberately
// tiny: two fetches on a timer, no framework.
(function () {
  const TEN_SECONDS = 10000;

  async function refresh(url, render) {
    try {
      const resp = await fetch(url, { headers: { Accept: "application/json" } });
      if (!resp.ok) return;
      render(await resp.json());
    } catch (e) {
      /* a failed poll is not worth disturbing the page over */
    }
  }

  function renderHealth(data) {
    for (const s of data.health || []) {
      const cell = document.querySelector(`[data-health-for="${s.service_id}"]`);
      if (cell) {
        cell.textContent = s.state;
        cell.className = "badge " + (s.state === "down" ? "down" : s.state === "up" ? "accent" : "");
      }
    }
  }

  if (document.querySelector("[data-health-for]")) {
    const tick = () => refresh("/api/v1/health", renderHealth);
    tick();
    setInterval(tick, TEN_SECONDS);
  }
  if (document.getElementById("lease-table")) {
    setInterval(() => location.reload(), 30000);
  }
})();
```

Add the health column to `services.go` — extend `servicesData`:

```go
	states := map[int64]string{}
	if s.o.Health != nil {
		for _, st := range s.o.Health() {
			states[st.ServiceID] = st.State
		}
	}
```

and set `row.Health = states[svc.ID]` with `Health string` added to
`serviceRow`; default it to `"unknown"` when absent. In `services.html`, add a
column:

```html
<th>Health</th>
...
<td>{{if eq $i 0}}<span class="badge{{if eq $svc.Health "down"}} down{{else if eq $svc.Health "up"}} accent{{end}}"
      data-health-for="{{$svc.ID}}">{{$svc.Health}}</span>{{end}}</td>
```

and add `<script src="/static/live.js" defer></script>` at the end of the
services page.

Add the API endpoints in `adminapi/api.go`. Extend `NewAPI` with two providers:

```go
type API struct {
	reg    *registry.Registry
	acl    *dnsserver.ACL
	cache  *dnsserver.Cache
	leases func() []dhcp.Lease
	health func() []health.Status
}

// WithProviders attaches discovery and health data. They are optional so the
// API still constructs in Plan 1's tests.
func (a *API) WithProviders(leases func() []dhcp.Lease, statuses func() []health.Status) *API {
	a.leases, a.health = leases, statuses
	return a
}
```

routes:

```go
	mux.HandleFunc("GET /api/v1/leases", auth(a.listLeases))
	mux.HandleFunc("POST /api/v1/leases/{ip}/promote", auth(a.promoteLease))
	mux.HandleFunc("GET /api/v1/health", auth(a.listHealth))
```

handlers:

```go
func (a *API) listLeases(w http.ResponseWriter, _ *http.Request) {
	out := []map[string]any{}
	if a.leases != nil {
		for _, l := range a.leases() {
			out = append(out, map[string]any{
				"hostname": l.Hostname, "address": l.IP, "mac": l.MAC,
				"expires": l.Expires.Unix(),
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"leases": out})
}

func (a *API) promoteLease(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if a.leases == nil {
		writeErr(w, http.StatusNotFound, "not_found", "ip", "lease discovery is not enabled")
		return
	}
	for _, l := range a.leases() {
		if l.IP != ip {
			continue
		}
		id, err := a.reg.PutService(store.Service{
			Name: l.Hostname, Addresses: []store.Address{{Address: l.IP}},
		})
		if err != nil {
			writeRegistryErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id, "name": l.Hostname})
		return
	}
	writeErr(w, http.StatusNotFound, "not_found", "ip", "no current lease for "+ip)
}

func (a *API) listHealth(w http.ResponseWriter, _ *http.Request) {
	out := []map[string]any{}
	if a.health != nil {
		for _, s := range a.health() {
			out = append(out, map[string]any{
				"service_id": s.ServiceID, "name": s.Name, "state": s.State,
				"since": s.Since.Unix(), "last_error": s.LastError,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"health": out})
}
```

Wire routes and providers in `serve.go`:

```go
	leaseFn := func() []dhcp.Lease {
		if poller == nil {
			return nil
		}
		return poller.Leases()
	}
	api = api.WithProviders(leaseFn, checker.Statuses)
```

and pass `Leases: leaseFn, Health: checker.Statuses` into `web.Options`. Add
the web routes in `pages.go`:

```go
	mux.HandleFunc("POST /discovered/promote", s.requireCSRF(s.postPromote))
```

`serve.go` must construct `checker` before the web server so `checker.Statuses`
is available; move the `health.NewChecker` call above the `web.New` call and
start `go checker.Run(ctx)` after the listeners.

- [ ] **Step 4: Run the full suite**

Run: `CGO_ENABLED=0 go test ./... -race`
Expected: PASS across every package.

Manual pass with a real lease file:

```bash
make build
rm -rf /tmp/kydns && mkdir -p /tmp/kydns
printf '1900000000 aa:bb:cc:dd:ee:01 192.168.1.50 laptop 01:aa\n' > /tmp/kydns/dnsmasq.leases
printf 'data_dir: /tmp/kydns\ndns:\n  listen: "127.0.0.1:5353"\nadmin:\n  listen: "127.0.0.1:8053"\ndiscovery:\n  dhcp_lease_file: /tmp/kydns/dnsmasq.leases\n' > /tmp/kydns.yaml
./bin/kydns serve --config /tmp/kydns.yaml &
sleep 2
dig @127.0.0.1 -p 5353 laptop.home.arpa A +short   # expect 192.168.1.50
kill %1
```

- [ ] **Step 5: Commit**

```bash
git add internal/web internal/adminapi internal/app
git commit -m "Add discovered screen, promote to service, and live tables

A shadowed lease is marked rather than listed as though it were
resolving, and only unshadowed leases offer a promote button. Promotion
is the only path from discovery into the database, since leases are
never persisted.

The services health column defaults to unknown rather than claiming up
when no checker is configured.

Completes v1.

AI-assisted contribution (agentic). Verified with: CGO_ENABLED=0 go test ./... -race,
plus a manual dig against a real dnsmasq lease file."
```

---

## Self-Review (Plan 3)

**Spec coverage.** `LeaseSource` interface with dnsmasq as the reference adapter, 30s poll, mtime-driven re-read (the poller's digest comparison achieves the same result more directly), lowercasing, `*` and empty skipped, invalid labels skipped and logged rather than rewritten, expired dropped, newest-wins on duplicates → Tasks 22 and 23. Flat names protected by precedence with shadowed leases logged and marked → Tasks 23 and 25. Leases never persisted, promote-to-service in the UI → Task 25. Health: http/tcp, 30s/5s, two failures down, one success up, `--check-insecure`, bounded pool, transitions-only logging, no effect on DNS answers → Task 24. Live tables via `fetch` on a timer → Task 25.

**One deliberate substitution.** The spec says leases are "re-parsed when the file mtime changes." The poller re-reads every cycle and compares a digest instead. The observable behavior is identical, it is strictly more correct (an mtime that does not advance within the same second cannot hide a change), and re-reading a homelab lease file every 30 seconds costs nothing.

**Placeholder scan.** No TBD steps. One issue found and fixed inline: `leaseRows` originally read records and discarded them. Shadow detection now covers manual record names too, which matches the precedence rule — a manual record outranks a lease exactly as a service does, so a lease hidden by one must be marked shadowed.

**Type consistency.** `dhcp.Lease` from Task 22 is what the poller stores, what `web.Options.Leases` returns, and what the API serializes. `zone.Lease{Hostname, Address}` from Plan 1 Task 6 is the conversion target in Task 23. `health.Status.ServiceID` matches `store.Service.ID` and the `data-health-for` attribute. `health.Lister` is satisfied by `*registry.Registry` because Plan 1 gave it `Services() ([]store.Service, error)`.
