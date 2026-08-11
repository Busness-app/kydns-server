# KyDNS Core Resolver Implementation Plan — Part 2 (Tasks 7–11)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Continues:** `2026-08-11-kydns-core.md` (Tasks 1–6). Read its **Global Constraints** first — they apply to every task here.

**Goal of this part:** turn the per-view snapshot into a running DNS server: atomic snapshot swapping, the query ACL with refusal counters, authoritative answers, forwarding with a cache, and the wired-up listeners.

**New dependency introduced here:** `github.com/miekg/dns` (Task 9), `golang.org/x/sync/singleflight` (Task 10).

---

### Task 7: Snapshot holder

**Files:**
- Create: `internal/zone/holder.go`
- Test: `internal/zone/holder_test.go`

**Interfaces:**
- Consumes: `zone.Build`, `zone.Input`, `zone.Snapshot` (Task 6).
- Produces:
  - `type Source func() (Input, error)` — pulls current registry contents
  - `type Holder struct{ ... }`
  - `func NewHolder(src Source) *Holder`
  - `func (h *Holder) Rebuild() error` — build fully, then swap; on error the old snapshot stays
  - `func (h *Holder) Current() *Snapshot` — lock-free read, nil before the first successful build
  - `func (h *Holder) Generation() uint32`

- [ ] **Step 1: Write the failing test**

```go
// internal/zone/holder_test.go
package zone

import (
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func TestRebuildSwapsSnapshot(t *testing.T) {
	addr := "192.168.1.20"
	h := NewHolder(func() (Input, error) {
		return Input{
			Zone:         "home.arpa.",
			ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			Services: []store.Service{{
				ID: 1, Name: "kypost", Addresses: []store.Address{{Address: addr}},
			}},
		}, nil
	})
	if h.Current() != nil {
		t.Fatal("Current() before first Rebuild should be nil")
	}
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	if got := h.Current().Lookup("", "kypost.home.arpa."); len(got) != 1 || got[0].Value != "192.168.1.20" {
		t.Fatalf("after first rebuild = %+v", got)
	}
	addr = "192.168.1.21"
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	if got := h.Current().Lookup("", "kypost.home.arpa."); got[0].Value != "192.168.1.21" {
		t.Errorf("after second rebuild = %q, want the new address", got[0].Value)
	}
}

func TestGenerationIncrementsPerRebuild(t *testing.T) {
	h := NewHolder(func() (Input, error) { return Input{Zone: "home.arpa."}, nil })
	for want := uint32(1); want <= 3; want++ {
		if err := h.Rebuild(); err != nil {
			t.Fatal(err)
		}
		if got := h.Current().Generation; got != want {
			t.Errorf("Generation = %d, want %d", got, want)
		}
	}
}

// A failed build must never take DNS dark: the previous snapshot keeps serving.
func TestFailedRebuildKeepsPreviousSnapshot(t *testing.T) {
	fail := false
	h := NewHolder(func() (Input, error) {
		if fail {
			return Input{}, errors.New("source unavailable")
		}
		return Input{
			Zone:     "home.arpa.",
			Services: []store.Service{{ID: 1, Name: "nas", Addresses: []store.Address{{Address: "192.168.1.30"}}}},
		}, nil
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	before := h.Current()

	fail = true
	if err := h.Rebuild(); err == nil {
		t.Fatal("Rebuild() error = nil, want the source error")
	}
	if h.Current() != before {
		t.Error("snapshot was replaced by a failed rebuild")
	}
	if got := h.Current().Lookup("", "nas.home.arpa."); len(got) != 1 {
		t.Error("previous snapshot stopped answering after a failed rebuild")
	}
}

// An invalid registry state (CNAME conflict) must fail the build, not panic
// or install a half-built snapshot.
func TestInvalidInputFailsBuild(t *testing.T) {
	h := NewHolder(func() (Input, error) {
		return Input{
			Zone:     "home.arpa.",
			Services: []store.Service{{ID: 1, Name: "kypost", Addresses: []store.Address{{Address: "192.168.1.20"}}}},
			Records:  []store.Record{{Name: "kypost.home.arpa.", Type: "CNAME", Value: "nas.home.arpa."}},
		}, nil
	})
	if err := h.Rebuild(); err == nil {
		t.Fatal("Rebuild() error = nil, want CNAME conflict")
	}
	if h.Current() != nil {
		t.Error("a failed first build installed a snapshot")
	}
}

func TestConcurrentReadsDuringRebuild(t *testing.T) {
	h := NewHolder(func() (Input, error) {
		return Input{
			Zone:     "home.arpa.",
			Services: []store.Service{{ID: 1, Name: "nas", Addresses: []store.Address{{Address: "192.168.1.30"}}}},
		}, nil
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if s := h.Current(); s == nil || len(s.Lookup("", "nas.home.arpa.")) != 1 {
					t.Error("reader saw an inconsistent snapshot")
					return
				}
			}
		}()
	}
	for j := 0; j < 50; j++ {
		if err := h.Rebuild(); err != nil {
			t.Error(err)
			break
		}
	}
	wg.Wait()
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/zone/ -run 'TestRebuild|TestGeneration|TestFailed|TestInvalidInput|TestConcurrent' -v`
Expected: FAIL — `undefined: NewHolder`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/zone/holder.go
package zone

import "sync/atomic"

// Source pulls the current registry contents. It returns an error rather than
// partial data so a transient store failure cannot silently empty the zone.
type Source func() (Input, error)

// Holder owns the live snapshot. Readers on the DNS hot path call Current with
// no lock; writers call Rebuild, which builds fully before swapping the
// pointer. A failed build leaves the previous snapshot in place.
type Holder struct {
	src  Source
	cur  atomic.Pointer[Snapshot]
	gen  atomic.Uint32
}

func NewHolder(src Source) *Holder { return &Holder{src: src} }

// Rebuild pulls fresh input, builds a complete snapshot, and swaps it in. It
// is all-or-nothing: any error returns before the swap.
func (h *Holder) Rebuild() error {
	in, err := h.src()
	if err != nil {
		return err
	}
	// Reserve the generation before building so the SOA serial always advances,
	// even across a failed attempt. Serials must never go backwards.
	in.Generation = h.gen.Add(1)
	snap, err := Build(in)
	if err != nil {
		return err
	}
	h.cur.Store(snap)
	return nil
}

// Current returns the live snapshot, or nil before the first successful build.
func (h *Holder) Current() *Snapshot { return h.cur.Load() }

// Generation is the current SOA serial.
func (h *Holder) Generation() uint32 { return h.gen.Load() }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/zone/ -race -v`
Expected: PASS with no race detected. `-race` is the point of `TestConcurrentReadsDuringRebuild`.

- [ ] **Step 5: Commit**

```bash
git add internal/zone/holder.go internal/zone/holder_test.go
git commit -m "Add atomic snapshot holder with all-or-nothing rebuild

The generation is reserved before the build so the SOA serial advances
even across a failed attempt; serials must never go backwards.

AI-assisted contribution (agentic). Verified with: go test -race ./internal/zone/"
```

---

### Task 8: Query ACL and refusal counters

**Files:**
- Create: `internal/dnsserver/acl.go`
- Test: `internal/dnsserver/acl_test.go`

**Interfaces:**
- Consumes: `config.TailscaleCGNAT`.
- Produces:
  - `type ACL struct{ ... }`
  - `func NewACL(allowed []netip.Prefix) *ACL`
  - `func (a *ACL) Allow(addr netip.Addr) bool` — increments counters on refusal
  - `type RefusalStats struct { Total, CGNAT uint64; LastCGNAT int64 }`
  - `func (a *ACL) Stats() RefusalStats`
  - `func (a *ACL) RecentCGNATRefusal(within time.Duration) bool`

- [ ] **Step 1: Write the failing test**

```go
// internal/dnsserver/acl_test.go
package dnsserver

import (
	"net/netip"
	"testing"
	"time"
)

func prefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestACLAllowsListedAndRefusesOthers(t *testing.T) {
	a := NewACL(prefixes(t, "192.168.0.0/16", "127.0.0.0/8"))
	for in, want := range map[string]bool{
		"192.168.1.5":     true,
		"127.0.0.1":       true,
		"8.8.8.8":         false,
		"100.101.102.103": false,
	} {
		if got := a.Allow(netip.MustParseAddr(in)); got != want {
			t.Errorf("Allow(%s) = %v, want %v", in, got, want)
		}
	}
}

// A dual-stack listener reports v4 peers as ::ffff:a.b.c.d.
func TestACLUnmapsV4InV6(t *testing.T) {
	a := NewACL(prefixes(t, "192.168.1.0/24"))
	if !a.Allow(netip.MustParseAddr("::ffff:192.168.1.5")) {
		t.Error("v4-mapped address refused, want allowed")
	}
}

func TestACLCountsRefusalsAndBucketsCGNAT(t *testing.T) {
	a := NewACL(prefixes(t, "192.168.0.0/16"))
	a.Allow(netip.MustParseAddr("192.168.1.5"))   // allowed, not counted
	a.Allow(netip.MustParseAddr("8.8.8.8"))       // refused, not CGNAT
	a.Allow(netip.MustParseAddr("100.64.0.1"))    // refused, CGNAT
	a.Allow(netip.MustParseAddr("100.127.255.1")) // refused, CGNAT

	s := a.Stats()
	if s.Total != 3 {
		t.Errorf("Total = %d, want 3", s.Total)
	}
	if s.CGNAT != 2 {
		t.Errorf("CGNAT = %d, want 2", s.CGNAT)
	}
	if s.LastCGNAT == 0 {
		t.Error("LastCGNAT = 0, want a timestamp")
	}
}

// 100.128.0.1 is outside 100.64.0.0/10 and must not land in the CGNAT bucket.
func TestACLCGNATBoundary(t *testing.T) {
	a := NewACL(nil)
	a.Allow(netip.MustParseAddr("100.128.0.1"))
	if s := a.Stats(); s.CGNAT != 0 {
		t.Errorf("CGNAT = %d for an address outside the range, want 0", s.CGNAT)
	}
}

func TestRecentCGNATRefusal(t *testing.T) {
	a := NewACL(nil)
	if a.RecentCGNATRefusal(time.Hour) {
		t.Error("RecentCGNATRefusal() = true with no refusals")
	}
	a.Allow(netip.MustParseAddr("100.64.0.1"))
	if !a.RecentCGNATRefusal(time.Hour) {
		t.Error("RecentCGNATRefusal() = false right after a refusal")
	}
	if a.RecentCGNATRefusal(0) {
		t.Error("RecentCGNATRefusal(0) = true, want false for a zero window")
	}
}

func TestEmptyACLRefusesEverything(t *testing.T) {
	if NewACL(nil).Allow(netip.MustParseAddr("192.168.1.1")) {
		t.Error("empty ACL allowed a query, want default-closed")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/dnsserver/ -v`
Expected: FAIL — `undefined: NewACL`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/dnsserver/acl.go
// Package dnsserver answers DNS queries from the zone snapshot and forwards
// everything else.
package dnsserver

import (
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/config"
)

var cgnat = netip.MustParsePrefix(config.TailscaleCGNAT)

// RefusalStats is a point-in-time read of the ACL counters. It carries counts
// and a timestamp only — never a source address — so it costs nothing against
// the logging policy and does not depend on the client-IP flag.
type RefusalStats struct {
	Total     uint64
	CGNAT     uint64
	LastCGNAT int64 // unix seconds, 0 if never
}

// ACL is the query allow-list. It is default-closed: an empty allow list
// refuses everything.
type ACL struct {
	allowed   []netip.Prefix
	total     atomic.Uint64
	cgnat     atomic.Uint64
	lastCGNAT atomic.Int64
	now       func() time.Time // swappable for tests
}

func NewACL(allowed []netip.Prefix) *ACL {
	masked := make([]netip.Prefix, 0, len(allowed))
	for _, p := range allowed {
		masked = append(masked, p.Masked())
	}
	return &ACL{allowed: masked, now: time.Now}
}

// Allow reports whether addr may query, counting refusals. Refusals are
// otherwise invisible, which is the worst possible thing to debug, so the
// counters feed /stats and the dashboard banner.
func (a *ACL) Allow(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range a.allowed {
		if p.Contains(addr) {
			return true
		}
	}
	a.total.Add(1)
	if cgnat.Contains(addr) {
		a.cgnat.Add(1)
		a.lastCGNAT.Store(a.now().Unix())
	}
	return false
}

func (a *ACL) Stats() RefusalStats {
	return RefusalStats{
		Total:     a.total.Load(),
		CGNAT:     a.cgnat.Load(),
		LastCGNAT: a.lastCGNAT.Load(),
	}
}

// RecentCGNATRefusal drives condition 1 of the dashboard banner.
func (a *ACL) RecentCGNATRefusal(within time.Duration) bool {
	last := a.lastCGNAT.Load()
	if last == 0 {
		return false
	}
	return a.now().Sub(time.Unix(last, 0)) < within
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dnsserver/ -v`
Expected: PASS, six tests.

- [ ] **Step 5: Commit**

```bash
git add internal/dnsserver
git commit -m "Add query ACL with refusal counters

Default-closed: an empty allow list refuses everything. Refusals are
bucketed into total and CGNAT with a last-seen timestamp so a closed
allow_tailscale has a loud failure mode instead of a silent one.

AI-assisted contribution (agentic). Verified with: go test ./internal/dnsserver/"
```

---

### Task 9: Authoritative answers

**Files:**
- Create: `internal/dnsserver/auth.go`
- Test: `internal/dnsserver/auth_test.go`

**Interfaces:**
- Consumes: `zone.Snapshot`, `zone.RR`.
- Produces:
  - `type Authoritative struct { Zone string; TTL uint32; ReverseZones []netip.Prefix }`
  - `func (a *Authoritative) Owns(qname string) bool`
  - `func (a *Authoritative) Answer(snap *zone.Snapshot, view string, q dns.Question) *dns.Msg` — returns nil when the name is not ours
  - `func (a *Authoritative) SOA(serial uint32) *dns.SOA`

- [ ] **Step 1: Write the failing test**

```go
// internal/dnsserver/auth_test.go
package dnsserver

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)

func testSnap(t *testing.T) *zone.Snapshot {
	t.Helper()
	s, err := zone.Build(zone.Input{
		Zone:         "home.arpa.",
		Generation:   7,
		ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Views:        []store.View{{Name: "tailnet", Subnets: []string{"100.64.0.0/10"}}},
		Services: []store.Service{{
			ID: 1, Name: "kypost",
			Addresses: []store.Address{
				{Address: "192.168.1.20"},
				{Address: "100.101.102.103", View: "tailnet"},
			},
			Aliases: []string{"webmail"},
		}},
		Records: []store.Record{
			{Name: "mail.home.arpa.", Type: "CNAME", Value: "kypost.home.arpa."},
			{Name: "out.home.arpa.", Type: "CNAME", Value: "example.com."},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func authority(t *testing.T) *Authoritative {
	t.Helper()
	return &Authoritative{
		Zone: "home.arpa.", TTL: 60,
		ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	}
}

func ask(t *testing.T, view, name string, qtype uint16) *dns.Msg {
	t.Helper()
	return authority(t).Answer(testSnap(t), view, dns.Question{
		Name: name, Qtype: qtype, Qclass: dns.ClassINET,
	})
}

func TestAnswerReturnsNilOutsideZone(t *testing.T) {
	if m := ask(t, "", "example.com.", dns.TypeA); m != nil {
		t.Fatalf("Answer() = %v for an out-of-zone name, want nil", m)
	}
}

func TestAnswerSplitHorizon(t *testing.T) {
	m := ask(t, "", "kypost.home.arpa.", dns.TypeA)
	if len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "192.168.1.20" {
		t.Fatalf("default view answer = %v", m.Answer)
	}
	if !m.Authoritative {
		t.Error("AA bit not set on an authoritative answer")
	}
	m = ask(t, "tailnet", "kypost.home.arpa.", dns.TypeA)
	if len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "100.101.102.103" {
		t.Fatalf("tailnet answer = %v", m.Answer)
	}
}

func TestAnswerNODATA(t *testing.T) {
	m := ask(t, "", "kypost.home.arpa.", dns.TypeAAAA)
	if m.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Errorf("Answer = %v, want empty for NODATA", m.Answer)
	}
	if len(m.Ns) != 1 {
		t.Fatalf("Ns = %v, want one SOA", m.Ns)
	}
	if _, ok := m.Ns[0].(*dns.SOA); !ok {
		t.Errorf("Ns[0] = %T, want *dns.SOA", m.Ns[0])
	}
}

func TestAnswerNXDOMAIN(t *testing.T) {
	m := ask(t, "", "nope.home.arpa.", dns.TypeA)
	if m.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
	}
	if len(m.Ns) != 1 {
		t.Errorf("Ns = %v, want one SOA", m.Ns)
	}
}

func TestCNAMEChasedInZone(t *testing.T) {
	m := ask(t, "", "mail.home.arpa.", dns.TypeA)
	if len(m.Answer) != 2 {
		t.Fatalf("Answer = %v, want CNAME plus the chased A", m.Answer)
	}
	if _, ok := m.Answer[0].(*dns.CNAME); !ok {
		t.Errorf("Answer[0] = %T, want *dns.CNAME", m.Answer[0])
	}
	if a, ok := m.Answer[1].(*dns.A); !ok || a.A.String() != "192.168.1.20" {
		t.Errorf("Answer[1] = %v, want the chased A record", m.Answer[1])
	}
}

func TestCNAMEOutOfZoneNotChased(t *testing.T) {
	m := ask(t, "", "out.home.arpa.", dns.TypeA)
	if len(m.Answer) != 1 {
		t.Fatalf("Answer = %v, want the CNAME alone", m.Answer)
	}
	if _, ok := m.Answer[0].(*dns.CNAME); !ok {
		t.Errorf("Answer[0] = %T, want *dns.CNAME", m.Answer[0])
	}
}

func TestSOASerialIsGeneration(t *testing.T) {
	m := ask(t, "", "nope.home.arpa.", dns.TypeA)
	soa := m.Ns[0].(*dns.SOA)
	if soa.Serial != 7 {
		t.Errorf("SOA serial = %d, want the snapshot generation 7", soa.Serial)
	}
}

func TestApexSOAAndNS(t *testing.T) {
	m := ask(t, "", "home.arpa.", dns.TypeSOA)
	if len(m.Answer) != 1 {
		t.Fatalf("SOA query answer = %v", m.Answer)
	}
	m = ask(t, "", "home.arpa.", dns.TypeNS)
	if len(m.Answer) != 1 {
		t.Fatalf("NS query answer = %v", m.Answer)
	}
	if ns, ok := m.Answer[0].(*dns.NS); !ok || ns.Ns != "ns.home.arpa." {
		t.Errorf("NS = %v, want ns.home.arpa.", m.Answer[0])
	}
}

func TestReversePerView(t *testing.T) {
	m := ask(t, "", "20.1.168.192.in-addr.arpa.", dns.TypePTR)
	if len(m.Answer) != 1 {
		t.Fatalf("PTR answer = %v", m.Answer)
	}
	if p := m.Answer[0].(*dns.PTR); p.Ptr != "kypost.home.arpa." {
		t.Errorf("PTR = %q, want kypost.home.arpa.", p.Ptr)
	}
}

// An .arpa name outside every configured reverse zone is not ours: it must
// return nil so the pipeline forwards it rather than answering NXDOMAIN.
func TestUnconfiguredReverseZoneNotOwned(t *testing.T) {
	if m := ask(t, "", "1.2.0.192.in-addr.arpa.", dns.TypePTR); m != nil {
		t.Fatalf("Answer() = %v for an unconfigured reverse zone, want nil", m)
	}
}

func TestTTLApplied(t *testing.T) {
	m := ask(t, "", "kypost.home.arpa.", dns.TypeA)
	if ttl := m.Answer[0].Header().Ttl; ttl != 60 {
		t.Errorf("TTL = %d, want 60", ttl)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/dnsserver/ -run 'TestAnswer|TestCNAME|TestSOA|TestApex|TestReverse|TestUnconfigured|TestTTL' -v`
Expected: FAIL — `undefined: Authoritative`.

- [ ] **Step 3: Write minimal implementation**

```bash
go get github.com/miekg/dns
```

```go
// internal/dnsserver/auth.go
package dnsserver

import (
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)

const cnameChaseDepth = 8

// Authoritative answers from the snapshot for names inside the private zone
// and the configured reverse zones.
type Authoritative struct {
	Zone         string // FQDN with trailing dot
	TTL          uint32
	ReverseZones []netip.Prefix
}

// Owns reports whether qname falls in a zone this server is authoritative for.
// A reverse name outside every configured reverse zone is not owned, so the
// pipeline forwards it instead of answering NXDOMAIN for the whole internet.
func (a *Authoritative) Owns(qname string) bool {
	n := strings.ToLower(dns.Fqdn(qname))
	if n == a.Zone || strings.HasSuffix(n, "."+a.Zone) {
		return true
	}
	if strings.HasSuffix(n, ".in-addr.arpa.") || strings.HasSuffix(n, ".ip6.arpa.") {
		addr, ok := addrFromArpa(n)
		if !ok {
			return false
		}
		for _, p := range a.ReverseZones {
			if p.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// SOA synthesizes the apex SOA. The serial is the snapshot generation, so it
// advances on every rebuild for free.
func (a *Authoritative) SOA(serial uint32) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: a.Zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: a.TTL},
		Ns:      "ns." + a.Zone,
		Mbox:    "hostmaster." + a.Zone,
		Serial:  serial,
		Refresh: 3600, Retry: 600, Expire: 604800, Minttl: a.TTL,
	}
}

// Answer builds the authoritative reply, or returns nil when the name is not
// ours and the caller should forward.
func (a *Authoritative) Answer(snap *zone.Snapshot, view string, q dns.Question) *dns.Msg {
	if snap == nil || !a.Owns(q.Name) {
		return nil
	}
	m := new(dns.Msg)
	m.Authoritative = true
	m.Question = []dns.Question{q}
	name := strings.ToLower(dns.Fqdn(q.Name))

	if name == a.Zone {
		switch q.Qtype {
		case dns.TypeSOA:
			m.Answer = []dns.RR{a.SOA(snap.Generation)}
		case dns.TypeNS:
			m.Answer = []dns.RR{&dns.NS{
				Hdr: dns.RR_Header{Name: a.Zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: a.TTL},
				Ns:  "ns." + a.Zone,
			}}
			m.Extra = []dns.RR{}
		default:
			m.Ns = []dns.RR{a.SOA(snap.Generation)}
		}
		return m
	}

	if q.Qtype == dns.TypePTR {
		if target := snap.LookupPTR(view, name); target != "" {
			m.Answer = []dns.RR{&dns.PTR{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: a.TTL},
				Ptr: dns.Fqdn(target),
			}}
			return m
		}
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{a.SOA(snap.Generation)}
		return m
	}

	rrs := snap.Lookup(view, name)
	if len(rrs) == 0 {
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{a.SOA(snap.Generation)}
		return m
	}

	// A CNAME is the only record at its name, so this branch is exclusive.
	if rrs[0].Type == "CNAME" {
		m.Answer = a.chase(snap, view, name, rrs[0].Value, q.Qtype, 0)
		return m
	}

	for _, rr := range rrs {
		if converted := a.toRR(rr, q.Qtype); converted != nil {
			m.Answer = append(m.Answer, converted)
		}
	}
	if len(m.Answer) == 0 { // name exists, type does not: NODATA
		m.Ns = []dns.RR{a.SOA(snap.Generation)}
	}
	return m
}

// chase follows in-zone CNAME targets so the client gets one complete answer.
// Out-of-zone targets are returned alone for the client's resolver to continue.
func (a *Authoritative) chase(snap *zone.Snapshot, view, name, target string, qtype uint16, depth int) []dns.RR {
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: a.TTL},
		Target: dns.Fqdn(target),
	}
	if depth >= cnameChaseDepth || qtype == dns.TypeCNAME || !a.Owns(target) {
		return []dns.RR{cname}
	}
	out := []dns.RR{cname}
	next := snap.Lookup(view, dns.Fqdn(target))
	for _, rr := range next {
		if rr.Type == "CNAME" {
			return append(out, a.chase(snap, view, dns.Fqdn(target), rr.Value, qtype, depth+1)...)
		}
		if converted := a.toRR(rr, qtype); converted != nil {
			out = append(out, converted)
		}
	}
	return out
}

func (a *Authoritative) toRR(rr zone.RR, qtype uint16) dns.RR {
	hdr := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: rr.Name, Rrtype: t, Class: dns.ClassINET, Ttl: a.TTL}
	}
	switch rr.Type {
	case "A":
		if qtype != dns.TypeA && qtype != dns.TypeANY {
			return nil
		}
		return &dns.A{Hdr: hdr(dns.TypeA), A: net.ParseIP(rr.Value)}
	case "AAAA":
		if qtype != dns.TypeAAAA && qtype != dns.TypeANY {
			return nil
		}
		return &dns.AAAA{Hdr: hdr(dns.TypeAAAA), AAAA: net.ParseIP(rr.Value)}
	}
	return nil
}

// addrFromArpa parses a reverse name back into an address.
func addrFromArpa(name string) (netip.Addr, bool) {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	switch {
	case strings.HasSuffix(n, ".in-addr.arpa"):
		parts := strings.Split(strings.TrimSuffix(n, ".in-addr.arpa"), ".")
		if len(parts) != 4 {
			return netip.Addr{}, false
		}
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		a, err := netip.ParseAddr(strings.Join(parts, "."))
		return a, err == nil
	case strings.HasSuffix(n, ".ip6.arpa"):
		nib := strings.Split(strings.TrimSuffix(n, ".ip6.arpa"), ".")
		if len(nib) != 32 {
			return netip.Addr{}, false
		}
		var sb strings.Builder
		for i := len(nib) - 1; i >= 0; i-- {
			sb.WriteString(nib[i])
			if i%4 == 0 && i != 0 {
				sb.WriteByte(':')
			}
		}
		a, err := netip.ParseAddr(sb.String())
		return a, err == nil
	}
	return netip.Addr{}, false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dnsserver/ -v`
Expected: PASS, all ACL and authoritative tests.

- [ ] **Step 5: Commit**

```bash
git add internal/dnsserver go.mod go.sum
git commit -m "Add authoritative answers with per-view lookup

Owns() treats a reverse name outside every configured reverse zone as
not ours, so it forwards rather than answering NXDOMAIN for addresses
we know nothing about. SOA serial is the snapshot generation.

AI-assisted contribution (agentic). Verified with: go test ./internal/dnsserver/"
```

---

### Task 10: Cache and forwarder

**Files:**
- Create: `internal/dnsserver/cache.go`, `internal/dnsserver/forward.go`
- Test: `internal/dnsserver/cache_test.go`, `internal/dnsserver/forward_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `type Cache struct{ ... }`, `func NewCache(maxEntries, minTTL, maxTTL, negMaxTTL int) *Cache`
  - `func (c *Cache) Get(q dns.Question) (*dns.Msg, bool)`, `func (c *Cache) Put(q dns.Question, m *dns.Msg)`, `func (c *Cache) Flush()`, `func (c *Cache) Len() int`
  - `type Exchanger interface { Exchange(context.Context, *dns.Msg, string) (*dns.Msg, error) }`
  - `type Forwarder struct{ ... }`, `func NewForwarder(upstreams []string, timeout time.Duration, c *Cache, x Exchanger) *Forwarder`
  - `func (f *Forwarder) Resolve(ctx context.Context, q dns.Question) (*dns.Msg, error)`
  - `func (f *Forwarder) Upstreams() []string`

- [ ] **Step 1: Write the failing test**

```go
// internal/dnsserver/cache_test.go
package dnsserver

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func reply(name string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   []byte{192, 0, 2, 1},
	}}
	return m
}

func question(name string) dns.Question {
	return dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
}

func TestCacheRoundTrip(t *testing.T) {
	c := NewCache(10, 5, 3600, 300)
	q := question("a.example.com.")
	if _, ok := c.Get(q); ok {
		t.Fatal("Get() on an empty cache returned a hit")
	}
	c.Put(q, reply("a.example.com.", 300))
	m, ok := c.Get(q)
	if !ok {
		t.Fatal("Get() after Put() missed")
	}
	if len(m.Answer) != 1 {
		t.Fatalf("cached answer = %v", m.Answer)
	}
}

// The key is case-insensitive on qname, matching DNS semantics.
func TestCacheKeyIsCaseInsensitive(t *testing.T) {
	c := NewCache(10, 5, 3600, 300)
	c.Put(question("A.Example.COM."), reply("A.Example.COM.", 300))
	if _, ok := c.Get(question("a.example.com.")); !ok {
		t.Error("Get() missed on a case-differing qname")
	}
}

func TestCacheClampsTTL(t *testing.T) {
	c := NewCache(10, 30, 120, 300)
	c.Put(question("low.example.com."), reply("low.example.com.", 5))
	m, _ := c.Get(question("low.example.com."))
	if ttl := m.Answer[0].Header().Ttl; ttl != 30 {
		t.Errorf("TTL = %d, want clamped up to the 30s minimum", ttl)
	}
	c.Put(question("high.example.com."), reply("high.example.com.", 9999))
	m, _ = c.Get(question("high.example.com."))
	if ttl := m.Answer[0].Header().Ttl; ttl != 120 {
		t.Errorf("TTL = %d, want clamped down to the 120s maximum", ttl)
	}
}

func TestCacheDecrementsTTLByAge(t *testing.T) {
	c := NewCache(10, 5, 3600, 300)
	now := time.Now()
	c.now = func() time.Time { return now }
	c.Put(question("a.example.com."), reply("a.example.com.", 100))

	now = now.Add(40 * time.Second)
	m, ok := c.Get(question("a.example.com."))
	if !ok {
		t.Fatal("entry expired early")
	}
	if ttl := m.Answer[0].Header().Ttl; ttl != 60 {
		t.Errorf("TTL = %d, want 60 after 40s of age", ttl)
	}
}

func TestCacheExpires(t *testing.T) {
	c := NewCache(10, 5, 3600, 300)
	now := time.Now()
	c.now = func() time.Time { return now }
	c.Put(question("a.example.com."), reply("a.example.com.", 30))

	now = now.Add(31 * time.Second)
	if _, ok := c.Get(question("a.example.com.")); ok {
		t.Error("Get() returned an expired entry")
	}
}

// RFC 2308: negative answers are cached using the SOA MINIMUM, clamped by
// negMaxTTL.
func TestNegativeCachingUsesSOAMinimum(t *testing.T) {
	c := NewCache(10, 5, 3600, 60)
	m := new(dns.Msg)
	m.Rcode = dns.RcodeNameError
	m.Ns = []dns.RR{&dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Minttl: 900,
	}}
	q := question("nope.example.com.")
	c.Put(q, m)

	now := time.Now()
	c.now = func() time.Time { return now.Add(70 * time.Second) }
	if _, ok := c.Get(q); ok {
		t.Error("negative entry outlived the clamped 60s maximum")
	}
}

func TestCacheEvictsOldest(t *testing.T) {
	c := NewCache(2, 5, 3600, 300)
	for _, n := range []string{"a.example.com.", "b.example.com.", "c.example.com."} {
		c.Put(question(n), reply(n, 300))
	}
	if c.Len() > 2 {
		t.Errorf("Len() = %d, want at most 2", c.Len())
	}
	if _, ok := c.Get(question("c.example.com.")); !ok {
		t.Error("the newest entry was evicted")
	}
}

func TestCacheFlush(t *testing.T) {
	c := NewCache(10, 5, 3600, 300)
	c.Put(question("a.example.com."), reply("a.example.com.", 300))
	c.Flush()
	if c.Len() != 0 {
		t.Errorf("Len() = %d after Flush(), want 0", c.Len())
	}
}
```

```go
// internal/dnsserver/forward_test.go
package dnsserver

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fakeExchanger struct {
	mu      sync.Mutex
	calls   atomic.Int64
	perAddr map[string]func() (*dns.Msg, error)
	delay   time.Duration
}

func (f *fakeExchanger) Exchange(_ context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
	f.calls.Add(1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.mu.Lock()
	fn, ok := f.perAddr[addr]
	f.mu.Unlock()
	if !ok {
		return nil, errors.New("no upstream configured: " + addr)
	}
	resp, err := fn()
	if resp != nil {
		resp.SetReply(m)
		resp.Answer = reply(m.Question[0].Name, 300).Answer
	}
	return resp, err
}

func okReply() (*dns.Msg, error) { return new(dns.Msg), nil }
func failReply() (*dns.Msg, error) {
	return nil, errors.New("timeout")
}

func TestForwarderUsesFirstWorkingUpstream(t *testing.T) {
	x := &fakeExchanger{perAddr: map[string]func() (*dns.Msg, error){
		"1.1.1.1:53": failReply,
		"9.9.9.9:53": okReply,
	}}
	f := NewForwarder([]string{"1.1.1.1:53", "9.9.9.9:53"}, time.Second, NewCache(10, 5, 3600, 300), x)
	m, err := f.Resolve(context.Background(), question("a.example.com."))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Answer) != 1 {
		t.Errorf("Answer = %v, want the second upstream's reply", m.Answer)
	}
	if got := x.calls.Load(); got != 2 {
		t.Errorf("upstream calls = %d, want 2 (one failure, one success)", got)
	}
}

func TestForwarderAllUpstreamsDown(t *testing.T) {
	x := &fakeExchanger{perAddr: map[string]func() (*dns.Msg, error){
		"1.1.1.1:53": failReply,
		"9.9.9.9:53": failReply,
	}}
	f := NewForwarder([]string{"1.1.1.1:53", "9.9.9.9:53"}, time.Second, NewCache(10, 5, 3600, 300), x)
	if _, err := f.Resolve(context.Background(), question("a.example.com.")); err == nil {
		t.Fatal("Resolve() error = nil, want an error when every upstream fails")
	}
}

func TestForwarderServesFromCache(t *testing.T) {
	x := &fakeExchanger{perAddr: map[string]func() (*dns.Msg, error){"1.1.1.1:53": okReply}}
	f := NewForwarder([]string{"1.1.1.1:53"}, time.Second, NewCache(10, 5, 3600, 300), x)
	for i := 0; i < 3; i++ {
		if _, err := f.Resolve(context.Background(), question("a.example.com.")); err != nil {
			t.Fatal(err)
		}
	}
	if got := x.calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d, want 1 with the rest served from cache", got)
	}
}

// The boot-time stampede: many identical concurrent misses must collapse into
// one upstream query.
func TestForwarderSingleFlight(t *testing.T) {
	x := &fakeExchanger{
		perAddr: map[string]func() (*dns.Msg, error){"1.1.1.1:53": okReply},
		delay:   50 * time.Millisecond,
	}
	f := NewForwarder([]string{"1.1.1.1:53"}, time.Second, NewCache(10, 5, 3600, 300), x)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.Resolve(context.Background(), question("a.example.com.")); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := x.calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d, want exactly 1 collapsed query", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/dnsserver/ -run 'TestCache|TestNegative|TestForwarder' -v`
Expected: FAIL — `undefined: NewCache`.

- [ ] **Step 3: Write minimal implementation**

```bash
go get golang.org/x/sync
```

```go
// internal/dnsserver/cache.go
package dnsserver

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheKey struct {
	name  string
	qtype uint16
}

type cacheEntry struct {
	key     cacheKey
	msg     *dns.Msg
	stored  time.Time
	expires time.Time
	ttl     uint32
}

// Cache holds forwarded responses. Authoritative answers are never cached —
// they already live in the snapshot.
type Cache struct {
	mu         sync.Mutex
	entries    map[cacheKey]*list.Element
	order      *list.List // front is newest
	maxEntries int
	minTTL     uint32
	maxTTL     uint32
	negMaxTTL  uint32
	now        func() time.Time
}

func NewCache(maxEntries, minTTL, maxTTL, negMaxTTL int) *Cache {
	return &Cache{
		entries:    map[cacheKey]*list.Element{},
		order:      list.New(),
		maxEntries: maxEntries,
		minTTL:     uint32(minTTL),
		maxTTL:     uint32(maxTTL),
		negMaxTTL:  uint32(negMaxTTL),
		now:        time.Now,
	}
}

func keyFor(q dns.Question) cacheKey {
	return cacheKey{name: strings.ToLower(dns.Fqdn(q.Name)), qtype: q.Qtype}
}

// Get returns a copy of the cached message with TTLs decremented by age.
func (c *Cache) Get(q dns.Question) (*dns.Msg, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[keyFor(q)]
	if !ok {
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	now := c.now()
	if !now.Before(e.expires) {
		c.removeLocked(el)
		return nil, false
	}
	c.order.MoveToFront(el)
	age := uint32(now.Sub(e.stored).Seconds())
	out := e.msg.Copy()
	for _, section := range [][]dns.RR{out.Answer, out.Ns, out.Extra} {
		for _, rr := range section {
			h := rr.Header()
			if h.Ttl > age {
				h.Ttl -= age
			} else {
				h.Ttl = 0
			}
		}
	}
	return out, true
}

// Put stores a response, clamping its TTL. Negative answers use the SOA
// MINIMUM per RFC 2308, clamped by negMaxTTL.
func (c *Cache) Put(q dns.Question, m *dns.Msg) {
	if m == nil {
		return
	}
	ttl := c.ttlFor(m)
	if ttl == 0 {
		return
	}
	stored := c.now()
	entry := &cacheEntry{
		key: keyFor(q), msg: m.Copy(), stored: stored,
		expires: stored.Add(time.Duration(ttl) * time.Second), ttl: ttl,
	}
	// Normalize stored TTLs so Get's age subtraction starts from the clamp.
	for _, section := range [][]dns.RR{entry.msg.Answer, entry.msg.Ns, entry.msg.Extra} {
		for _, rr := range section {
			rr.Header().Ttl = ttl
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[entry.key]; ok {
		c.removeLocked(el)
	}
	c.entries[entry.key] = c.order.PushFront(entry)
	for c.order.Len() > c.maxEntries {
		c.removeLocked(c.order.Back())
	}
}

func (c *Cache) ttlFor(m *dns.Msg) uint32 {
	if m.Rcode == dns.RcodeNameError || len(m.Answer) == 0 {
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				return clamp(soa.Minttl, c.minTTL, c.negMaxTTL)
			}
		}
		return 0 // nothing authoritative to base a negative TTL on
	}
	lowest := ^uint32(0)
	for _, rr := range m.Answer {
		if t := rr.Header().Ttl; t < lowest {
			lowest = t
		}
	}
	return clamp(lowest, c.minTTL, c.maxTTL)
}

func clamp(v, lo, hi uint32) uint32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (c *Cache) removeLocked(el *list.Element) {
	if el == nil {
		return
	}
	delete(c.entries, el.Value.(*cacheEntry).key)
	c.order.Remove(el)
}

func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[cacheKey]*list.Element{}
	c.order.Init()
}

func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
```

```go
// internal/dnsserver/forward.go
package dnsserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// Exchanger sends one query to one upstream. The interface exists so tests do
// not need real sockets, and so DoT or DoH can be added as another
// implementation without touching the handler.
type Exchanger interface {
	Exchange(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error)
}

// UDPExchanger is the plain UDP/TCP client. A truncated UDP reply is retried
// over TCP.
type UDPExchanger struct{ Timeout time.Duration }

func (u UDPExchanger) Exchange(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
	udp := &dns.Client{Net: "udp", Timeout: u.Timeout}
	resp, _, err := udp.ExchangeContext(ctx, m, addr)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: u.Timeout}
		resp, _, err = tcp.ExchangeContext(ctx, m, addr)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// Forwarder resolves non-authoritative queries through the cache and, on a
// miss, the upstream list in order.
type Forwarder struct {
	upstreams []string
	timeout   time.Duration
	cache     *Cache
	x         Exchanger
	group     singleflight.Group
}

func NewForwarder(upstreams []string, timeout time.Duration, c *Cache, x Exchanger) *Forwarder {
	return &Forwarder{upstreams: upstreams, timeout: timeout, cache: c, x: x}
}

func (f *Forwarder) Upstreams() []string { return f.upstreams }

// Resolve answers from cache, or collapses concurrent identical misses into a
// single upstream query. That collapse is what survives the boot-time
// stampede when every device on the LAN wakes at once.
func (f *Forwarder) Resolve(ctx context.Context, q dns.Question) (*dns.Msg, error) {
	if m, ok := f.cache.Get(q); ok {
		return m, nil
	}
	key := fmt.Sprintf("%s|%d", strings.ToLower(dns.Fqdn(q.Name)), q.Qtype)
	v, err, _ := f.group.Do(key, func() (any, error) {
		if m, ok := f.cache.Get(q); ok {
			return m, nil
		}
		m, err := f.exchange(ctx, q)
		if err != nil {
			return nil, err
		}
		f.cache.Put(q, m)
		return m, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*dns.Msg).Copy(), nil
}

func (f *Forwarder) exchange(ctx context.Context, q dns.Question) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(q.Name), q.Qtype)
	req.SetEdns0(1232, false)

	var lastErr error
	for _, addr := range f.upstreams {
		attempt, cancel := context.WithTimeout(ctx, f.timeout)
		resp, err := f.x.Exchange(attempt, req, addr)
		cancel()
		if err == nil && resp != nil && resp.Rcode != dns.RcodeServerFailure {
			return resp, nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("upstream %s returned %s", addr, dns.RcodeToString[resp.Rcode])
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no upstreams configured")
	}
	return nil, fmt.Errorf("all upstreams failed: %w", lastErr)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dnsserver/ -race -v`
Expected: PASS. `TestForwarderSingleFlight` must report exactly 1 upstream call.

- [ ] **Step 5: Commit**

```bash
git add internal/dnsserver go.mod go.sum
git commit -m "Add response cache and upstream forwarder

Cache decrements TTLs by age, clamps into [min, max], and applies RFC
2308 negative caching from the SOA MINIMUM. The forwarder fails over
sequentially and collapses identical concurrent misses through
singleflight, which is what survives the boot-time stampede.

AI-assisted contribution (agentic). Verified with: go test -race ./internal/dnsserver/"
```

---

### Task 11: Server pipeline and listeners

**Files:**
- Create: `internal/dnsserver/server.go`
- Test: `internal/dnsserver/server_test.go`

**Interfaces:**
- Consumes: `ACL`, `Authoritative`, `Forwarder`, `zone.Holder`.
- Produces:
  - `type Options struct { Holder *zone.Holder; ACL *ACL; Auth *Authoritative; Forwarder *Forwarder; LogQueries, LogClientIP bool; Logger *slog.Logger }`
  - `type Server struct{ ... }`, `func New(o Options) *Server`
  - `func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg)`
  - `func (s *Server) ListenAndServe(addr string) error`, `func (s *Server) Shutdown(ctx context.Context) error`

- [ ] **Step 1: Write the failing test**

```go
// internal/dnsserver/server_test.go
package dnsserver

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)

// newTestServer starts a real UDP listener on 127.0.0.1 and returns its
// address. Views match the /32 loopback addresses the tests dial from.
func newTestServer(t *testing.T, allow []netip.Prefix) string {
	t.Helper()
	h := zone.NewHolder(func() (zone.Input, error) {
		return zone.Input{
			Zone:         "home.arpa.",
			ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			Views: []store.View{
				{Name: "lan", Subnets: []string{"127.0.0.2/32"}},
				{Name: "tailnet", Subnets: []string{"127.0.0.3/32"}},
			},
			Services: []store.Service{{
				ID: 1, Name: "kypost",
				Addresses: []store.Address{
					{Address: "192.168.1.20"},
					{Address: "100.101.102.103", View: "tailnet"},
				},
			}},
		}, nil
	})
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	x := &fakeExchanger{perAddr: map[string]func() (*dns.Msg, error){"1.1.1.1:53": okReply}}
	srv := New(Options{
		Holder: h,
		ACL:    NewACL(allow),
		Auth: &Authoritative{
			Zone: "home.arpa.", TTL: 60,
			ReverseZones: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		},
		Forwarder: NewForwarder([]string{"1.1.1.1:53"}, time.Second, NewCache(10, 5, 3600, 300), x),
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ds := &dns.Server{PacketConn: pc, Handler: srv}
	go ds.ActivateAndServe()
	t.Cleanup(func() { ds.Shutdown() })
	return pc.LocalAddr().String()
}

// queryFrom dials with an explicit local source address so the server's view
// matcher sees a different client each time.
func queryFrom(t *testing.T, server, source, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c := &dns.Client{
		Net:     "udp",
		Timeout: 2 * time.Second,
		Dialer:  &net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(source)}},
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		t.Fatalf("exchange from %s: %v", source, err)
	}
	return resp
}

func allowLoopback(t *testing.T) []netip.Prefix {
	return prefixes(t, "127.0.0.0/8")
}

// The headline behavior: one name, two source addresses, two answers.
func TestSplitHorizonOverTheWire(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))

	lan := queryFrom(t, addr, "127.0.0.2", "kypost.home.arpa.", dns.TypeA)
	if len(lan.Answer) != 1 || lan.Answer[0].(*dns.A).A.String() != "192.168.1.20" {
		t.Fatalf("lan answer = %v, want 192.168.1.20", lan.Answer)
	}
	tail := queryFrom(t, addr, "127.0.0.3", "kypost.home.arpa.", dns.TypeA)
	if len(tail.Answer) != 1 || tail.Answer[0].(*dns.A).A.String() != "100.101.102.103" {
		t.Fatalf("tailnet answer = %v, want 100.101.102.103", tail.Answer)
	}
}

func TestRefusedWhenOutsideACL(t *testing.T) {
	addr := newTestServer(t, prefixes(t, "192.168.0.0/16"))
	resp := queryFrom(t, addr, "127.0.0.2", "kypost.home.arpa.", dns.TypeA)
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
}

func TestForwardsUnknownName(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))
	resp := queryFrom(t, addr, "127.0.0.2", "example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Errorf("forwarded reply = %v rcode %s", resp.Answer, dns.RcodeToString[resp.Rcode])
	}
	if resp.Authoritative {
		t.Error("AA bit set on a forwarded answer")
	}
}

func TestNXDOMAINInsideZone(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))
	resp := queryFrom(t, addr, "127.0.0.2", "nope.home.arpa.", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
}

func TestNotImplementedForNonQueryOpcode(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("kypost.home.arpa.", dns.TypeA)
	m.Opcode = dns.OpcodeStatus
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeNotImplemented {
		t.Errorf("Rcode = %s, want NOTIMP", dns.RcodeToString[resp.Rcode])
	}
}

func TestRefusedForNonINClass(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	m := new(dns.Msg)
	m.Question = []dns.Question{{Name: "kypost.home.arpa.", Qtype: dns.TypeA, Qclass: dns.ClassCHAOS}}
	m.Id = dns.Id()
	m.RecursionDesired = true
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
}

func TestServfailWhenSnapshotMissingAndUpstreamsDown(t *testing.T) {
	h := zone.NewHolder(func() (zone.Input, error) { return zone.Input{Zone: "home.arpa."}, nil })
	x := &fakeExchanger{perAddr: map[string]func() (*dns.Msg, error){"1.1.1.1:53": failReply}}
	srv := New(Options{
		Holder:    h, // never rebuilt: Current() is nil
		ACL:       NewACL(prefixes(t, "127.0.0.0/8")),
		Auth:      &Authoritative{Zone: "home.arpa.", TTL: 60},
		Forwarder: NewForwarder([]string{"1.1.1.1:53"}, time.Second, NewCache(10, 5, 3600, 300), x),
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ds := &dns.Server{PacketConn: pc, Handler: srv}
	go ds.ActivateAndServe()
	defer ds.Shutdown()

	resp := queryFrom(t, pc.LocalAddr().String(), "127.0.0.1", "example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("Rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
}

func TestShutdownIsClean(t *testing.T) {
	srv := New(Options{
		Holder: zone.NewHolder(func() (zone.Input, error) { return zone.Input{Zone: "home.arpa."}, nil }),
		ACL:    NewACL(nil),
		Auth:   &Authoritative{Zone: "home.arpa.", TTL: 60},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() on a server that never listened = %v, want nil", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/dnsserver/ -run 'TestSplitHorizon|TestRefused|TestForwards|TestNXDOMAIN|TestNotImplemented|TestServfail|TestShutdown' -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/dnsserver/server.go
package dnsserver

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)

type Options struct {
	Holder      *zone.Holder
	ACL         *ACL
	Auth        *Authoritative
	Forwarder   *Forwarder
	LogQueries  bool
	LogClientIP bool
	Logger      *slog.Logger
}

type Server struct {
	o    Options
	mu   sync.Mutex
	srvs []*dns.Server
}

func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Server{o: o}
}

// ServeDNS is the whole pipeline: opcode and class checks, ACL, view
// resolution, authoritative lookup, then forwarding.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()
	reply := func(m *dns.Msg, source, view string) {
		if err := w.WriteMsg(m); err != nil {
			s.o.Logger.Warn("write reply", "error", err)
		}
		s.logQuery(r, m, w, source, view, time.Since(start))
	}
	fail := func(rcode int, source string) {
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		reply(m, source, "")
	}

	if r.Opcode != dns.OpcodeQuery {
		fail(dns.RcodeNotImplemented, "opcode")
		return
	}
	if len(r.Question) != 1 {
		fail(dns.RcodeFormatError, "question")
		return
	}
	q := r.Question[0]
	if q.Qclass != dns.ClassINET {
		fail(dns.RcodeRefused, "class")
		return
	}

	src := sourceAddr(w)
	if !s.o.ACL.Allow(src) {
		fail(dns.RcodeRefused, "acl")
		return
	}

	snap := s.o.Holder.Current()
	view := ""
	if snap != nil {
		view = snap.Matcher.Match(src)
	}

	if m := s.o.Auth.Answer(snap, view, q); m != nil {
		m.SetRcode(r, m.Rcode)
		m.Authoritative = true
		reply(m, "authoritative", view)
		return
	}

	if s.o.Forwarder == nil {
		fail(dns.RcodeServerFailure, "forward")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := s.o.Forwarder.Resolve(ctx, q)
	if err != nil {
		s.o.Logger.Warn("forward failed", "qname", q.Name, "error", err)
		fail(dns.RcodeServerFailure, "forward")
		return
	}
	out := resp.Copy()
	out.SetRcode(r, resp.Rcode)
	out.Authoritative = false
	out.RecursionAvailable = true
	reply(out, "forward", view)
}

// sourceAddr extracts the client address, unmapped so v4-in-v6 peers match
// v4 rules.
func sourceAddr(w dns.ResponseWriter) netip.Addr {
	host, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// logQuery honors the two-flag policy: query logging is off by default, and
// the client IP needs its own separate flag.
func (s *Server) logQuery(r, m *dns.Msg, w dns.ResponseWriter, source, view string, d time.Duration) {
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
		"duration_ms", d.Milliseconds(),
	}
	if s.o.LogClientIP {
		args = append(args, "client", w.RemoteAddr().String())
	}
	s.o.Logger.Info("query", args...)
}

// ListenAndServe starts UDP and TCP listeners on addr and blocks until one
// fails.
func (s *Server) ListenAndServe(addr string) error {
	errs := make(chan error, 2)
	s.mu.Lock()
	for _, net := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: addr, Net: net, Handler: s}
		s.srvs = append(s.srvs, srv)
		go func() { errs <- srv.ListenAndServe() }()
	}
	s.mu.Unlock()
	return <-errs
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var joined error
	for _, srv := range s.srvs {
		if err := srv.ShutdownContext(ctx); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	s.srvs = nil
	return joined
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dnsserver/ -race -v`
Expected: PASS. If `TestSplitHorizonOverTheWire` fails to bind `127.0.0.2`, confirm the platform routes all of `127.0.0.0/8` to loopback — Linux does by default.

- [ ] **Step 5: Commit**

```bash
git add internal/dnsserver
git commit -m "Add DNS server pipeline with UDP and TCP listeners

Resolves the client view from the source address, answers from that
view's index, and forwards otherwise. Query logging stays off by
default and the client IP behind its own second flag.

AI-assisted contribution (agentic). Verified with: go test -race ./internal/dnsserver/"
```

---

## Self-Review (Part 2)

**Spec coverage.** All-or-nothing rebuild and SOA serial → Task 7. ACL default-closed, refusal counters, CGNAT bucket, `RecentCGNATRefusal` for the banner → Task 8. Authoritative table (answer, NODATA, NXDOMAIN, CNAME chase in and out of zone), SOA/NS synthesis, per-view PTR, unconfigured reverse zones forwarding → Task 9. TTL clamping, RFC 2308 negative caching, LRU, sequential failover, single-flight, EDNS0 and TCP retry → Task 10. Pipeline order, `NOTIMP`, `REFUSED`, `SERVFAIL`, query logging with the two-flag policy → Task 11.

**Placeholder scan.** No TBD steps; every code step is runnable. `Exchanger` is an interface so Task 10 and 11 tests need no sockets, and it is the stated extension point for DoT/DoH.

**Type consistency.** `zone.Holder.Current()` returns `*zone.Snapshot`, consumed by `Authoritative.Answer(snap, view, q)` in Tasks 9 and 11. `Matcher.Match` returns `""` for the default view, matching `Snapshot.Views[""]` from Task 6. `NewCache(maxEntries, minTTL, maxTTL, negMaxTTL)` has the same signature in Tasks 10 and 11. `prefixes`, `reply`, `question`, `fakeExchanger`, `okReply`, and `failReply` are defined once in Tasks 8 and 10 and reused in Task 11 — same package, no redeclaration.
