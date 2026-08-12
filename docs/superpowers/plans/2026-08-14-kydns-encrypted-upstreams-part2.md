# KyDNS Encrypted Upstreams Implementation Plan — Part 2

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

Continues [part 1](2026-08-14-kydns-encrypted-upstreams.md), which built the
`internal/upstream` package. The Global Constraints in part 1 apply to every
task here.

Part 1 delivered:
- `upstream.Transport` (`Plain`, `DoT`, `DoH`) with `String()` and `Secure()`
- `upstream.Spec{Raw, Transport, Addr, ServerName, URL, RootCAs}`, `Parse`, `ParseAll`
- `upstream.Upstream` — `Exchange(ctx, *dns.Msg) (*dns.Msg, error)`, `Secure() bool`, `String() string`
- `upstream.New(Spec, time.Duration) (Upstream, error)`, `upstream.NewAll([]string, time.Duration) ([]Upstream, error)`
- Working plaintext, DoT and DoH transports

---

## Task 5: Plumb the DO bit through the cache

The forwarder always speaks EDNS0 upstream but currently hardcodes `DO=0` and
keys the cache on name and type alone. Once the client's `DO` is forwarded, a
`DO=1` client and a `DO=0` client would share a cache entry and one of them
would get a response shaped for the other. This task fixes both, before any
`AD` handling depends on it.

**Files:**
- Modify: `internal/dnsserver/cache.go:12-15,50-52,55,86` — key, `keyFor`, `Get`, `Put`
- Modify: `internal/dnsserver/forward.go:60-107` — `Resolve` and `exchange` take `do`
- Modify: `internal/dnsserver/server.go:93-106` — read `DO`, strip `OPT`
- Test: `internal/dnsserver/cache_test.go`, `internal/dnsserver/forward_test.go`, `internal/dnsserver/server_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `func (c *Cache) Get(q dns.Question, do bool) (*dns.Msg, bool)`
  - `func (c *Cache) Put(q dns.Question, do bool, m *dns.Msg)`
  - `func (f *Forwarder) Resolve(ctx context.Context, q dns.Question, do bool) (*dns.Msg, error)`

- [ ] **Step 1: Write the failing tests**

Append to `internal/dnsserver/cache_test.go`:

```go
// A DO=1 client wants RRSIGs and a DO=0 client does not, so the two responses
// are different messages and must not share an entry.
func TestCacheSeparatesByDOBit(t *testing.T) {
	c := NewCache(10, 5, 3600, 300)
	q := question("a.example.com.")

	c.Put(q, true, reply("a.example.com.", 300))
	if _, ok := c.Get(q, false); ok {
		t.Error("Get(do=false) hit an entry stored with do=true")
	}
	if _, ok := c.Get(q, true); !ok {
		t.Error("Get(do=true) missed its own entry")
	}

	c.Put(q, false, reply("a.example.com.", 300))
	if _, ok := c.Get(q, false); !ok {
		t.Error("Get(do=false) missed after its own Put")
	}
}
```

Append to `internal/dnsserver/forward_test.go`:

```go
// The same name asked for with and without DO is two upstream queries, not one
// cache hit.
func TestForwarderDoesNotShareCacheAcrossDO(t *testing.T) {
	x := &fakeExchanger{perAddr: map[string]func() (*dns.Msg, error){"1.1.1.1:53": okReply}}
	f := newForwarder(x, "1.1.1.1:53")
	if _, err := f.Resolve(context.Background(), question("a.example.com."), false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Resolve(context.Background(), question("a.example.com."), true); err != nil {
		t.Fatal(err)
	}
	if got := x.calls.Load(); got != 2 {
		t.Errorf("upstream calls = %d, want 2 (DO=0 and DO=1 are different questions)", got)
	}
}
```

The assertion that the outbound query actually carries the client's `DO` needs
the fake to record what it was sent, which `fakeExchanger` does not do. Task 6
replaces that fake wholesale, so the assertion lands there
(`TestForwarderForwardsTheDOBit`) rather than growing a hook here that would be
deleted one task later.

Append to `internal/dnsserver/server_test.go`:

```go
// A client that did not offer EDNS0 must not be handed an OPT record back, even
// though the forwarder always uses EDNS0 upstream.
func TestForwardedReplyHasNoOPTForAPlainClient(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))
	resp := queryFrom(t, addr, "127.0.0.1", "example.com.", dns.TypeA)
	if resp.IsEdns0() != nil {
		t.Error("reply carries an OPT record the client never asked for")
	}
}

// A client that did ask for DNSSEC records still gets an OPT record back.
func TestForwardedReplyKeepsOPTForAnEDNSClient(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))
	c := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second,
		Dialer:  &net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}},
	}
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.SetEdns0(1232, true)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsEdns0() == nil {
		t.Error("reply dropped the OPT record an EDNS0 client asked for")
	}
}
```

Every other existing call to `f.Resolve(ctx, q)` in `forward_test.go` and
`server_test.go` gains a trailing `false`; the compiler lists each one.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/dnsserver/`
Expected: FAIL to compile — `too many arguments in call to c.Get`, `c.Put`, and `f.Resolve`.

- [ ] **Step 3: Add the DO bit to the cache key**

In `internal/dnsserver/cache.go`:

```go
type cacheKey struct {
	name  string
	qtype uint16
	do    bool
}
```

```go
func keyFor(q dns.Question, do bool) cacheKey {
	return cacheKey{name: strings.ToLower(dns.Fqdn(q.Name)), qtype: q.Qtype, do: do}
}
```

Change the two method signatures and their `keyFor` calls:

```go
func (c *Cache) Get(q dns.Question, do bool) (*dns.Msg, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[keyFor(q, do)]
```

```go
func (c *Cache) Put(q dns.Question, do bool, m *dns.Msg) {
```

and inside `Put`:

```go
	entry := &cacheEntry{
		key: keyFor(q, do), msg: m.Copy(), stored: stored,
		expires: stored.Add(time.Duration(ttl) * time.Second), ttl: ttl,
	}
```

- [ ] **Step 4: Update the existing cache tests**

`cache_test.go` has twenty existing `c.Get(...)` and `c.Put(...)` calls that
predate the DO bit. Every one of them is testing DO-independent behaviour, so
each takes `false`:

- `c.Get(q)` becomes `c.Get(q, false)`
- `c.Put(q, m)` becomes `c.Put(q, false, m)`

Run `go build ./internal/dnsserver/` and `go vet ./internal/dnsserver/` — the
compiler lists every remaining call site by line number. Do not add a
DO-varying case to any existing test; `TestCacheSeparatesByDOBit` from Step 1
is the one that covers it.

- [ ] **Step 5: Thread DO through the forwarder**

In `internal/dnsserver/forward.go`, replace `Resolve` and `exchange`:

```go
// Resolve answers from cache, or collapses concurrent identical misses into a
// single upstream query. That collapse is what survives the boot-time
// stampede when every device on the LAN wakes at once.
func (f *Forwarder) Resolve(ctx context.Context, q dns.Question, do bool) (*dns.Msg, error) {
	if m, ok := f.cache.Get(q, do); ok {
		return m, nil
	}
	key := fmt.Sprintf("%s|%d|%t", strings.ToLower(dns.Fqdn(q.Name)), q.Qtype, do)
	v, err, _ := f.group.Do(key, func() (any, error) {
		if m, ok := f.cache.Get(q, do); ok {
			return m, nil
		}
		m, err := f.exchange(ctx, q, do)
		if err != nil {
			return nil, err
		}
		f.cache.Put(q, do, m)
		return m, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*dns.Msg).Copy(), nil
}

func (f *Forwarder) exchange(ctx context.Context, q dns.Question, do bool) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(q.Name), q.Qtype)
	req.SetEdns0(1232, do)
```

The rest of `exchange` is unchanged in this task.

- [ ] **Step 6: Read DO in the server and strip OPT for plain clients**

In `internal/dnsserver/server.go`, replace the forwarding block (currently lines
93–106):

```go
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	edns := r.IsEdns0()
	resp, err := s.o.Forwarder.Resolve(ctx, q, edns != nil && edns.Do())
	if err != nil {
		s.o.Logger.Warn("forward failed", "qname", q.Name, "error", err)
		fail(dns.RcodeServerFailure, "forward")
		return
	}
	out := resp.Copy()
	rcode := resp.Rcode
	out.SetRcode(r, rcode)
	out.Authoritative = false
	out.RecursionAvailable = true
	if edns == nil {
		stripOPT(out)
	}
	reply(out, "forward", view)
```

Add below `sourceAddr`:

```go
// stripOPT removes the EDNS0 record from a response. The forwarder always
// speaks EDNS0 upstream, but a client that did not offer an OPT record must
// not be handed one back.
func stripOPT(m *dns.Msg) {
	extra := m.Extra[:0]
	for _, rr := range m.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	m.Extra = extra
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./internal/dnsserver/ -race -v`
Expected: PASS, including the four new tests.

Run: `go build ./... && go test ./...`
Expected: PASS across the repo.

- [ ] **Step 8: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/dnsserver/
git commit -m "Key the cache on the DO bit and forward it

A DO=1 client and a DO=0 client get different messages, so sharing an
entry hands one of them a response shaped for the other. A client that
sent no OPT record no longer gets one back."
```

---

## Task 6: Transport-aware forwarder and the AD policy

**Files:**
- Modify: `internal/dnsserver/forward.go` — delete `Exchanger` and `UDPExchanger`, hold `[]upstream.Upstream`, apply the `AD` policy, track status
- Modify: `internal/app/serve.go:122-125` — build upstreams
- Test: `internal/dnsserver/forward_test.go` (rewritten fakes), `internal/dnsserver/server_test.go` (three constructor call sites)

**Interfaces:**
- Consumes: `upstream.Upstream`, `upstream.NewAll` from part 1.
- Produces:
  - `type UpstreamStatus struct { Spec string; Secure bool; LastError string; LastErrAt time.Time; LastOKAt time.Time }`
  - `func NewForwarder(ups []upstream.Upstream, timeout time.Duration, c *Cache) *Forwarder`
  - `func (f *Forwarder) Status() []UpstreamStatus`
  - `func (f *Forwarder) Upstreams() []string` is **removed**.

- [ ] **Step 1: Replace the test fakes**

In `internal/dnsserver/forward_test.go`, delete `fakeExchanger`, `okReply`,
`failReply` and the old `newForwarder`, and put these in their place:

```go
// fakeUpstream stands in for a real resolver. secure decides whether the AD
// bit it sets is allowed to survive.
type fakeUpstream struct {
	name   string
	secure bool
	calls  atomic.Int64
	delay  time.Duration
	reply  func(*dns.Msg) (*dns.Msg, error)

	mu   sync.Mutex
	sent []*dns.Msg // queries as they went out
}

func (f *fakeUpstream) Secure() bool   { return f.secure }
func (f *fakeUpstream) String() string { return f.name }

func (f *fakeUpstream) Exchange(_ context.Context, m *dns.Msg) (*dns.Msg, error) {
	f.calls.Add(1)
	f.mu.Lock()
	f.sent = append(f.sent, m.Copy())
	f.mu.Unlock()
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return f.reply(m)
}

func (f *fakeUpstream) lastSent(t *testing.T) *dns.Msg {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		t.Fatal("no query reached the upstream")
	}
	return f.sent[len(f.sent)-1]
}

func okUpstream(name string, secure bool) *fakeUpstream {
	return &fakeUpstream{name: name, secure: secure, reply: func(m *dns.Msg) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Answer = reply(m.Question[0].Name, 300).Answer
		return resp, nil
	}}
}

// adUpstream answers with AD set, which is what a validating resolver does.
func adUpstream(name string, secure bool) *fakeUpstream {
	u := okUpstream(name, secure)
	inner := u.reply
	u.reply = func(m *dns.Msg) (*dns.Msg, error) {
		resp, err := inner(m)
		if resp != nil {
			resp.AuthenticatedData = true
		}
		return resp, err
	}
	return u
}

func deadUpstream(name string, secure bool) *fakeUpstream {
	return &fakeUpstream{name: name, secure: secure, reply: func(*dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("dial tcp: i/o timeout")
	}}
}

func servfailUpstream(name string, secure bool) *fakeUpstream {
	return &fakeUpstream{name: name, secure: secure, reply: func(m *dns.Msg) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Rcode = dns.RcodeServerFailure
		return resp, nil
	}}
}

func newForwarder(ups ...upstream.Upstream) *Forwarder {
	return NewForwarder(ups, time.Second, NewCache(10, 5, 3600, 300))
}
```

Add `"github.com/yoshiofthewire/kydns-server/internal/upstream"` to the imports.

Rewrite the existing tests in that file against the new fakes. The behaviour
each asserts is unchanged:

```go
func TestForwarderUsesFirstWorkingUpstream(t *testing.T) {
	bad, good := deadUpstream("tls://1.1.1.1:853", true), okUpstream("tls://9.9.9.9:853", true)
	f := newForwarder(bad, good)
	m, err := f.Resolve(context.Background(), question("a.example.com."), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Answer) != 1 {
		t.Errorf("Answer = %v, want the second upstream's reply", m.Answer)
	}
	if bad.calls.Load() != 1 || good.calls.Load() != 1 {
		t.Errorf("calls = %d then %d, want 1 each", bad.calls.Load(), good.calls.Load())
	}
}

// Strict is structural: an all-encrypted list with nothing reachable fails.
func TestForwarderAllUpstreamsDown(t *testing.T) {
	f := newForwarder(deadUpstream("tls://1.1.1.1:853", true), deadUpstream("tls://9.9.9.9:853", true))
	if _, err := f.Resolve(context.Background(), question("a.example.com."), false); err == nil {
		t.Fatal("Resolve() error = nil, want an error when every upstream fails")
	}
}

func TestForwarderNoUpstreamsConfigured(t *testing.T) {
	f := newForwarder()
	if _, err := f.Resolve(context.Background(), question("a.example.com."), false); err == nil {
		t.Error("Resolve() error = nil with no upstreams, want an error")
	}
}

func TestForwarderServesFromCache(t *testing.T) {
	u := okUpstream("tls://1.1.1.1:853", true)
	f := newForwarder(u)
	for i := 0; i < 3; i++ {
		if _, err := f.Resolve(context.Background(), question("a.example.com."), false); err != nil {
			t.Fatal(err)
		}
	}
	if got := u.calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d, want 1 with the rest served from cache", got)
	}
}

// The boot-time stampede: many identical concurrent misses must collapse into
// one upstream query.
func TestForwarderSingleFlight(t *testing.T) {
	u := okUpstream("tls://1.1.1.1:853", true)
	u.delay = 50 * time.Millisecond
	f := newForwarder(u)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.Resolve(context.Background(), question("a.example.com."), false); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := u.calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d, want exactly 1 collapsed query", got)
	}
}

// A SERVFAIL from one upstream must fail over rather than be returned.
func TestForwarderFailsOverOnServfail(t *testing.T) {
	bad, good := servfailUpstream("tls://1.1.1.1:853", true), okUpstream("tls://9.9.9.9:853", true)
	f := newForwarder(bad, good)
	if _, err := f.Resolve(context.Background(), question("a.example.com."), false); err != nil {
		t.Fatalf("Resolve() = %v, want failover to the healthy upstream", err)
	}
	if bad.calls.Load() != 1 || good.calls.Load() != 1 {
		t.Errorf("calls = %d then %d, want 1 each", bad.calls.Load(), good.calls.Load())
	}
}

func TestForwarderDoesNotShareCacheAcrossDO(t *testing.T) {
	u := okUpstream("tls://1.1.1.1:853", true)
	f := newForwarder(u)
	if _, err := f.Resolve(context.Background(), question("a.example.com."), false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Resolve(context.Background(), question("a.example.com."), true); err != nil {
		t.Fatal(err)
	}
	if got := u.calls.Load(); got != 2 {
		t.Errorf("upstream calls = %d, want 2 (DO=0 and DO=1 are different questions)", got)
	}
}

func TestForwarderForwardsTheDOBit(t *testing.T) {
	u := okUpstream("tls://1.1.1.1:853", true)
	f := newForwarder(u)
	for _, do := range []bool{false, true} {
		if _, err := f.Resolve(context.Background(), question("a.example.com."), do); err != nil {
			t.Fatal(err)
		}
		opt := u.lastSent(t).IsEdns0()
		if opt == nil {
			t.Fatal("outbound query has no OPT record")
		}
		if opt.Do() != do {
			t.Errorf("DO sent upstream = %v, want %v", opt.Do(), do)
		}
	}
}
```

Delete `TestForwarderUpstreams`; `TestForwarderStatus` below replaces it.

- [ ] **Step 2: Write the new failing tests for the AD policy and status**

Append to `internal/dnsserver/forward_test.go`:

```go
// The whole point of the exercise: a verdict only counts if the channel that
// carried it was authenticated.
func TestForwarderKeepsADFromASecureUpstream(t *testing.T) {
	f := newForwarder(adUpstream("tls://1.1.1.1:853", true))
	m, err := f.Resolve(context.Background(), question("a.example.com."), false)
	if err != nil {
		t.Fatal(err)
	}
	if !m.AuthenticatedData {
		t.Error("AD = false from an encrypted upstream that set it")
	}
}

func TestForwarderClearsADFromAPlaintextUpstream(t *testing.T) {
	f := newForwarder(adUpstream("udp://192.168.1.1:53", false))
	m, err := f.Resolve(context.Background(), question("a.example.com."), false)
	if err != nil {
		t.Fatal(err)
	}
	if m.AuthenticatedData {
		t.Error("AD = true from a plaintext upstream: nothing authenticated that answer")
	}
}

// Clearing AD at the source means the cache cannot resurrect it either.
func TestForwarderClearsADBeforeCaching(t *testing.T) {
	u := adUpstream("udp://192.168.1.1:53", false)
	f := newForwarder(u)
	if _, err := f.Resolve(context.Background(), question("a.example.com."), false); err != nil {
		t.Fatal(err)
	}
	m, err := f.Resolve(context.Background(), question("a.example.com."), false)
	if err != nil {
		t.Fatal(err)
	}
	if u.calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want the second answer to come from cache", u.calls.Load())
	}
	if m.AuthenticatedData {
		t.Error("AD = true on a cache hit from a plaintext upstream")
	}
}

// KyDNS never lets a client turn off the upstream's validation, and asks for
// the verdict on every query.
func TestForwarderQueriesWithCDClearAndADSet(t *testing.T) {
	u := okUpstream("tls://1.1.1.1:853", true)
	f := newForwarder(u)
	if _, err := f.Resolve(context.Background(), question("a.example.com."), false); err != nil {
		t.Fatal(err)
	}
	sent := u.lastSent(t)
	if sent.CheckingDisabled {
		t.Error("CD = true upstream: a client must not be able to skip validation")
	}
	if !sent.AuthenticatedData {
		t.Error("AD = false upstream: the verdict was never requested")
	}
}

// The escape hatch: a plaintext upstream after an encrypted one still answers,
// and its answer is honestly unauthenticated.
func TestForwarderFallsBackToPlaintextWhenConfiguredTo(t *testing.T) {
	f := newForwarder(deadUpstream("tls://1.1.1.1:853", true), adUpstream("udp://192.168.1.1:53", false))
	m, err := f.Resolve(context.Background(), question("a.example.com."), false)
	if err != nil {
		t.Fatalf("Resolve() = %v, want the configured plaintext fallback to answer", err)
	}
	if m.AuthenticatedData {
		t.Error("AD = true on the plaintext fallback's answer")
	}
}

// Without this, a firewall that blocks 853 looks like "the internet is broken".
func TestForwarderStatus(t *testing.T) {
	bad, good := deadUpstream("tls://1.1.1.1:853", true), okUpstream("udp://192.168.1.1:53", false)
	f := newForwarder(bad, good)

	st := f.Status()
	if len(st) != 2 {
		t.Fatalf("Status() returned %d entries, want 2", len(st))
	}
	if st[0].Spec != "tls://1.1.1.1:853" || !st[0].Secure {
		t.Errorf("Status()[0] = %+v, want the encrypted upstream", st[0])
	}
	if st[1].Secure {
		t.Errorf("Status()[1].Secure = true for a udp:// upstream")
	}
	if st[0].LastError != "" {
		t.Errorf("Status()[0].LastError = %q before any query", st[0].LastError)
	}

	if _, err := f.Resolve(context.Background(), question("a.example.com."), false); err != nil {
		t.Fatal(err)
	}
	st = f.Status()
	if !strings.Contains(st[0].LastError, "timeout") {
		t.Errorf("Status()[0].LastError = %q, want the dial failure", st[0].LastError)
	}
	if st[0].LastErrAt.IsZero() {
		t.Error("Status()[0].LastErrAt is zero after a failure")
	}
	if st[1].LastError != "" || st[1].LastOKAt.IsZero() {
		t.Errorf("Status()[1] = %+v, want a clean success", st[1])
	}
}
```

Add `"strings"` to the test imports.

- [ ] **Step 3: Fix the three server_test.go call sites**

`internal/dnsserver/server_test.go` builds forwarders in three places. Replace:

- line 52–60, in `newTestServer` — delete the `x := &fakeExchanger{...}` line and change `Forwarder: newForwarder(x, "1.1.1.1:53")` to:

```go
		Forwarder: newForwarder(okUpstream("tls://1.1.1.1:853", true)),
```

- line 158–163, in `TestServfailWhenSnapshotMissingAndUpstreamsDown` — delete the `x := ...` line and change the field to:

```go
		Forwarder: newForwarder(deadUpstream("tls://1.1.1.1:853", true)),
```

- line 183–188, in `TestAuthoritativeUnaffectedByUpstreamFailure` — the same replacement as the previous one.

- [ ] **Step 4: Add the authoritative-answer test**

Append to `internal/dnsserver/server_test.go`:

```go
// Authoritative answers are unsigned local data. Nothing validated them, so
// they must never claim to be authenticated.
func TestAuthoritativeAnswerNeverCarriesAD(t *testing.T) {
	addr := newTestServer(t, allowLoopback(t))
	for _, name := range []string{"kypost.home.arpa.", "20.1.168.192.in-addr.arpa."} {
		qtype := dns.TypeA
		if name != "kypost.home.arpa." {
			qtype = dns.TypePTR
		}
		resp := queryFrom(t, addr, "127.0.0.2", name, qtype)
		if resp.AuthenticatedData {
			t.Errorf("%s: AD = true on an unsigned local answer", name)
		}
	}
}
```

- [ ] **Step 5: Run the tests to verify they fail**

Run: `go test ./internal/dnsserver/`
Expected: FAIL to compile — `NewForwarder` still wants an `Exchanger`, and
`Status`, `UpstreamStatus` are undefined.

- [ ] **Step 6: Rewrite the forwarder**

Replace `internal/dnsserver/forward.go` entirely:

```go
package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/upstream"
	"golang.org/x/sync/singleflight"
)

// UpstreamStatus is what the last query to one upstream did. Without it, a
// firewall that blocks port 853 presents to the operator as "DNS is broken".
type UpstreamStatus struct {
	Spec      string
	Secure    bool
	LastError string
	LastErrAt time.Time
	LastOKAt  time.Time
}

// Forwarder resolves non-authoritative queries through the cache and, on a
// miss, the upstream list in order.
type Forwarder struct {
	ups     []upstream.Upstream
	timeout time.Duration
	cache   *Cache
	group   singleflight.Group

	mu     sync.Mutex
	status []UpstreamStatus
}

func NewForwarder(ups []upstream.Upstream, timeout time.Duration, c *Cache) *Forwarder {
	f := &Forwarder{ups: ups, timeout: timeout, cache: c, status: make([]UpstreamStatus, len(ups))}
	for i, u := range ups {
		f.status[i] = UpstreamStatus{Spec: u.String(), Secure: u.Secure()}
	}
	return f
}

// Status is a snapshot for the UI, copied so callers cannot race the recorder.
func (f *Forwarder) Status() []UpstreamStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]UpstreamStatus(nil), f.status...)
}

func (f *Forwarder) record(i int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		f.status[i].LastError = err.Error()
		f.status[i].LastErrAt = time.Now()
		return
	}
	f.status[i].LastError = ""
	f.status[i].LastOKAt = time.Now()
}

// Resolve answers from cache, or collapses concurrent identical misses into a
// single upstream query. That collapse is what survives the boot-time
// stampede when every device on the LAN wakes at once.
func (f *Forwarder) Resolve(ctx context.Context, q dns.Question, do bool) (*dns.Msg, error) {
	if m, ok := f.cache.Get(q, do); ok {
		return m, nil
	}
	key := fmt.Sprintf("%s|%d|%t", strings.ToLower(dns.Fqdn(q.Name)), q.Qtype, do)
	v, err, _ := f.group.Do(key, func() (any, error) {
		if m, ok := f.cache.Get(q, do); ok {
			return m, nil
		}
		m, err := f.exchange(ctx, q, do)
		if err != nil {
			return nil, err
		}
		f.cache.Put(q, do, m)
		return m, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*dns.Msg).Copy(), nil
}

func (f *Forwarder) exchange(ctx context.Context, q dns.Question, do bool) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(q.Name), q.Qtype)
	req.SetEdns0(1232, do)
	// The upstream is the validator, so it is never told to skip checking, and
	// AD asks for its verdict without the RRSIG payload (RFC 6840 5.7).
	req.CheckingDisabled = false
	req.AuthenticatedData = true

	if len(f.ups) == 0 {
		return nil, errors.New("no upstreams configured")
	}
	var lastErr error
	for i, u := range f.ups {
		attempt, cancel := context.WithTimeout(ctx, f.timeout)
		resp, err := u.Exchange(attempt, req)
		cancel()
		if err == nil && resp != nil && resp.Rcode != dns.RcodeServerFailure {
			if !u.Secure() {
				// Cleared here rather than at the response boundary, so a
				// plaintext answer cannot carry AD into the cache either.
				resp.AuthenticatedData = false
			}
			f.record(i, nil)
			return resp, nil
		}
		switch {
		case err != nil:
			lastErr = err
		case resp == nil:
			lastErr = fmt.Errorf("upstream %s returned no message", u)
		default:
			lastErr = fmt.Errorf("upstream %s returned %s", u, dns.RcodeToString[resp.Rcode])
		}
		f.record(i, lastErr)
	}
	return nil, fmt.Errorf("all upstreams failed: %w", lastErr)
}
```

`Exchanger`, `UDPExchanger` and `Upstreams()` are gone with the rewrite.

- [ ] **Step 7: Build the upstreams in serve.go**

In `internal/app/serve.go`, replace lines 122–125:

```go
	cache := dnsserver.NewCache(cfg.DNS.CacheEntries, cfg.DNS.CacheMinTTL, cfg.DNS.CacheMaxTTL, cfg.DNS.NegativeMaxTTL)
	ups, err := upstream.NewAll(cfg.DNS.Upstreams, 2*time.Second)
	if err != nil {
		return err
	}
	for _, u := range ups {
		if !u.Secure() {
			logger.Warn("upstream is unencrypted; answers from it cannot be authenticated",
				"upstream", u.String(),
				"fix", "use a tls:// or https:// upstream in dns.upstreams")
		}
	}
	fwd := dnsserver.NewForwarder(ups, 2*time.Second, cache)
```

Add `"github.com/yoshiofthewire/kydns-server/internal/upstream"` to the imports.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `go build ./... && go test ./... -race`
Expected: PASS across the repo.

- [ ] **Step 9: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/dnsserver/ internal/app/serve.go
git commit -m "Make the forwarder transport-aware and enforce the AD policy

AD is cleared the moment an answer arrives from an insecure upstream, so
no downstream code has to remember. Per-upstream status records why a
strict list is failing, which is the difference between a fixable
firewall rule and 'DNS is broken'."
```

---

## Task 7: Encrypted defaults and scheme validation

**Files:**
- Modify: `internal/config/config.go:127-129,152-160` — defaults and validation
- Modify: `kydns.example.yaml:30-32` — the upstreams block
- Test: `internal/config/config_test.go`, `internal/config/example_test.go`

**Interfaces:**
- Consumes: `upstream.ParseAll` from part 1.
- Produces: `dns.upstreams` defaults to `["tls://1.1.1.1:853", "tls://9.9.9.9:853"]`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/config/config_test.go`:

The file already has `write(t, body) string`, which writes a config body to a
temp file and returns its path. Both tests use it; do not add another helper.

```go
// Encryption is the default. An operator who does nothing gets a private path
// to the upstream.
func TestDefaultUpstreamsAreEncrypted(t *testing.T) {
	c, err := Load(write(t, "data_dir: /tmp/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.DNS.Upstreams) == 0 {
		t.Fatal("no default upstreams")
	}
	for _, u := range c.DNS.Upstreams {
		if !strings.HasPrefix(u, "tls://") {
			t.Errorf("default upstream %q is not encrypted", u)
		}
	}
}

func TestUpstreamValidation(t *testing.T) {
	body := func(u string) string {
		return "data_dir: /tmp/x\ndns:\n  upstreams: [\"" + u + "\"]\n"
	}
	for _, good := range []string{
		"tls://1.1.1.1:853", "https://9.9.9.9/dns-query", "udp://192.168.1.1:53", "1.1.1.1:53",
	} {
		if _, err := Load(write(t, body(good))); err != nil {
			t.Errorf("upstreams [%q] rejected: %v", good, err)
		}
	}
	for _, bad := range []string{"tls://dns.quad9.net:853", "quic://1.1.1.1:853", "1.1.1.1:no"} {
		if _, err := Load(write(t, body(bad))); err == nil {
			t.Errorf("upstreams [%q] accepted, want a rejection", bad)
		}
	}
}
```

Add `"strings"` to the test imports if it is not already there.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/config/ -run 'TestDefaultUpstreams|TestUpstreamValidation'`
Expected: FAIL — the default is still `1.1.1.1:53`, and `tls://dns.quad9.net:853` is accepted.

- [ ] **Step 3: Change the defaults**

In `internal/config/config.go`, replace lines 127–129:

```go
	if len(c.DNS.Upstreams) == 0 {
		c.DNS.Upstreams = []string{"tls://1.1.1.1:853", "tls://9.9.9.9:853"}
	}
```

- [ ] **Step 4: Delegate validation**

Replace lines 152–160:

```go
	if _, err := upstream.ParseAll(c.DNS.Upstreams); err != nil {
		return fmt.Errorf("dns.upstreams: %w", err)
	}
```

Add `"github.com/yoshiofthewire/kydns-server/internal/upstream"` to the imports,
and drop `"net"` if the compiler now reports it unused.

- [ ] **Step 5: Update the shipped example**

In `kydns.example.yaml`, replace the upstreams block (lines 30–32):

```yaml
  # Where non-local queries go, tried in order. The scheme is the policy:
  #
  #   tls://IP[:port]      DNS-over-TLS, port 853 by default
  #   https://IP[/path]    DNS-over-HTTPS, port 443 and /dns-query by default
  #   udp://IP[:port]      plain DNS — readable and forgeable in transit
  #
  # The host must be an IP address: a hostname would need DNS to resolve it,
  # and KyDNS may be the thing resolving. Add #name after the address when the
  # provider's certificate needs a hostname, e.g.
  # tls://45.90.28.0:853#abc123.dns.nextdns.io
  #
  # With only encrypted upstreams, a query fails with SERVFAIL rather than
  # falling back to plain DNS. That is deliberate. Adding a udp:// entry is the
  # escape hatch, and it gives up authentication for every answer it serves.
  upstreams: ["tls://1.1.1.1:853", "tls://9.9.9.9:853"]
  # upstreams: ["tls://1.1.1.1:853", "udp://192.168.1.1:53"]
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS, including `TestExampleConfigLoads`, `TestExampleMatchesDefaults`
and `TestExampleDocumentsEverySetting`, which now compare the encrypted defaults.

Run: `go test ./...`
Expected: PASS. `internal/web/settings_test.go` and `internal/web/auth_test.go`
build their own configs and are unaffected.

- [ ] **Step 7: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/config/ kydns.example.yaml
git commit -m "Default to encrypted upstreams

An operator who changes nothing now gets a private path to the resolver.
Validation delegates to upstream.ParseAll so the accepted grammar is
defined in exactly one place."
```

---

## Task 8: Show the upstreams and their failures

**Files:**
- Modify: `internal/web/middleware.go:30` — `Upstreams` becomes a status func
- Modify: `internal/web/banner.go` — add `PlaintextUpstreamBanner`
- Modify: `internal/web/dashboard.go`, `internal/web/templates/dashboard.html`
- Modify: `internal/web/settings.go`, `internal/web/templates/settings.html`
- Modify: `internal/app/serve.go:166` — pass `fwd.Status`
- Test: `internal/web/banner_test.go`, `internal/web/settings_test.go`

**Interfaces:**
- Consumes: `dnsserver.UpstreamStatus`, `(*dnsserver.Forwarder).Status` from Task 6.
- Produces:
  - `web.Options.Upstreams func() []dnsserver.UpstreamStatus`
  - `func PlaintextUpstreamBanner(statuses []dnsserver.UpstreamStatus) *Banner`
  - Template data key `Banners` (a `[]*Banner`) replaces `Banner`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/web/banner_test.go`:

```go
func TestPlaintextUpstreamBanner(t *testing.T) {
	secure := []dnsserver.UpstreamStatus{
		{Spec: "tls://1.1.1.1:853", Secure: true},
		{Spec: "https://9.9.9.9/dns-query", Secure: true},
	}
	if b := PlaintextUpstreamBanner(secure); b != nil {
		t.Errorf("banner = %+v with every upstream encrypted, want nil", b)
	}

	mixed := append(secure, dnsserver.UpstreamStatus{Spec: "udp://192.168.1.1:53"})
	b := PlaintextUpstreamBanner(mixed)
	if b == nil {
		t.Fatal("banner = nil with a plaintext upstream configured")
	}
	if !strings.Contains(b.Body, "udp://192.168.1.1:53") {
		t.Errorf("body %q does not name the plaintext upstream", b.Body)
	}
	if strings.Contains(b.Body, "tls://1.1.1.1:853") {
		t.Errorf("body %q names an encrypted upstream", b.Body)
	}
	if b.Fix == "" {
		t.Error("banner has no fix")
	}
}
```

`banner_test.go` already imports both `strings` and `dnsserver`, so no import
changes are needed there.

Append to `internal/web/settings_test.go`, using the same `loggedIn(t)` and
`page(t, h, path, c)` helpers the config-view tests at line 171 already use,
and setting the option directly on `srv.o` the way those tests set `srv.o.Config`:

```go
// Strict mode is only survivable if the operator can see why it is failing.
func TestSettingsShowsUpstreamStatus(t *testing.T) {
	h, srv, c, _ := loggedIn(t)
	srv.o.Upstreams = func() []dnsserver.UpstreamStatus {
		return []dnsserver.UpstreamStatus{
			{Spec: "tls://1.1.1.1:853", Secure: true, LastError: "dial tcp 1.1.1.1:853: i/o timeout"},
			{Spec: "udp://192.168.1.1:53"},
		}
	}
	body := page(t, h, "/settings", c)
	for _, want := range []string{
		"tls://1.1.1.1:853",
		"i/o timeout",
		"udp://192.168.1.1:53",
		"plaintext",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page does not contain %q", want)
		}
	}
}

// With no forwarder wired the card is absent rather than an empty table.
func TestSettingsOmitsUpstreamsWhenUnset(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	if strings.Contains(page(t, h, "/settings", c), "<h3>Upstreams</h3>") {
		t.Error("settings renders an upstream card with no forwarder wired")
	}
}
```

Add `"github.com/yoshiofthewire/kydns-server/internal/dnsserver"` to that
file's imports.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/web/`
Expected: FAIL — `undefined: PlaintextUpstreamBanner`, and `Options.Upstreams`
is still `[]string`.

- [ ] **Step 3: Change the Options field**

In `internal/web/middleware.go`, replace line 30:

```go
	AllowTailscale bool
	SetupToken     string
	Logger         *slog.Logger

	// Leases, Health and Upstreams are nil when the corresponding subsystem is
	// off, which the screens render as "not enabled" rather than as empty.
	Leases    func() []dhcp.Lease
	Health    func() []health.Status
	Upstreams func() []dnsserver.UpstreamStatus
```

(Remove the old `Upstreams []string` line and fold the field into the existing
nil-able block.)

- [ ] **Step 4: Add the banner**

Append to `internal/web/banner.go`:

```go
// PlaintextUpstreamBanner fires when any upstream is unencrypted. Encryption is
// the default, so a udp:// entry is always something someone chose, and the
// operator looking at this screen may not be the one who chose it.
func PlaintextUpstreamBanner(statuses []dnsserver.UpstreamStatus) *Banner {
	var names []string
	for _, s := range statuses {
		if !s.Secure {
			names = append(names, s.Spec)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return &Banner{
		Title: "Some upstream queries are unencrypted.",
		Body: fmt.Sprintf(
			"Plain DNS is used for %s. Anyone on the network path can read and forge those answers, so KyDNS clears the authenticated-data flag on everything they return.",
			strings.Join(names, ", ")),
		Fix: "Replace them with tls:// or https:// entries in dns.upstreams and restart KyDNS.",
	}
}
```

- [ ] **Step 5: Render both banners on the dashboard**

Replace `getDashboard` in `internal/web/dashboard.go`:

```go
func (s *Server) getDashboard(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Title": "Dashboard", "Nav": "dashboard"}

	var banners []*Banner
	if s.o.Upstreams != nil {
		up := s.o.Upstreams()
		data["Upstreams"] = up
		if b := PlaintextUpstreamBanner(up); b != nil {
			banners = append(banners, b)
		}
	}

	views, err := s.o.Registry.Views()
	if err != nil {
		data["Error"] = err.Error()
		data["Banners"] = banners
		s.render(w, r, "dashboard.html", data)
		return
	}
	svcs, err := s.o.Registry.Services()
	if err != nil {
		data["Error"] = err.Error()
	}
	recs, err := s.o.Registry.Records()
	if err != nil {
		data["Error"] = err.Error()
	}

	if b := TailscaleBanner(s.o.ACL, views, s.o.AllowTailscale, bannerWindow); b != nil {
		banners = append(banners, b)
	}
	data["Banners"] = banners
	data["Services"] = len(svcs)
	data["Records"] = len(recs)
	data["Views"] = len(views)
	if s.o.ACL != nil {
		st := s.o.ACL.Stats()
		data["RefusedTotal"] = st.Total
		data["RefusedCGNAT"] = st.CGNAT
	}
	if s.o.Cache != nil {
		data["CacheEntries"] = s.o.Cache.Len()
	}
	s.render(w, r, "dashboard.html", data)
}
```

In `internal/web/templates/dashboard.html`, replace the `{{with .Banner}}`
block with:

```html
{{range .Banners}}
<div class="banner">
  <strong>{{.Title}}</strong>
  <p>{{.Body}}</p>
  <p>{{.Fix}}</p>
</div>
{{end}}
```

and replace the Upstreams row:

```html
    <tr><td>Upstreams</td><td>{{range .Upstreams}}<span class="badge{{if not .Secure}} warn{{end}}">{{.Spec}}</span> {{else}}<span class="muted">none</span>{{end}}</td></tr>
```

- [ ] **Step 6: Add the settings table**

In `internal/web/settings.go`, add to `settingsData`'s returned map:

```go
		"Upstreams": s.upstreams(),
```

and add the accessor next to `configRows`:

```go
// upstreams is nil when the forwarder is not wired, which the template renders
// as "not enabled" rather than as an empty table.
func (s *Server) upstreams() []dnsserver.UpstreamStatus {
	if s.o.Upstreams == nil {
		return nil
	}
	return s.o.Upstreams()
}
```

Add `"github.com/yoshiofthewire/kydns-server/internal/dnsserver"` to that
file's imports.

In `internal/web/templates/settings.html`, insert a card before the
Configuration card:

```html
{{if .Upstreams}}
<div class="card">
  <h3>Upstreams</h3>
  <p class="muted">Tried in order. {{.RestartNote}}</p>
  <table class="grid">
    <tr><th>Upstream</th><th>Channel</th><th>Last result</th></tr>
    {{range .Upstreams}}
    <tr>
      <td><code>{{.Spec}}</code></td>
      <td>{{if .Secure}}encrypted{{else}}<span class="badge warn">plaintext</span>{{end}}</td>
      <td>
        {{if .LastError}}<span class="error">{{.LastError}}</span>
        {{else if .LastOKAt.IsZero}}<span class="muted">not used yet</span>
        {{else}}ok{{end}}
      </td>
    </tr>
    {{end}}
  </table>
  <p class="muted">An answer over a plaintext channel is served with the
     authenticated-data flag cleared, because nothing authenticated it.</p>
</div>
{{end}}
```

- [ ] **Step 7: Wire it in serve.go**

In `internal/app/serve.go`, replace line 166:

```go
			Upstreams:      fwd.Status,
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `go build ./... && go test ./... -race`
Expected: PASS. Existing dashboard tests that assert on Tailscale banner text
still pass, because the text is unchanged and `{{range .Banners}}` renders it.

- [ ] **Step 9: Drive the real binary**

Every plan so far found at least one bug this way that the tests missed. Build
and look at the screens:

```bash
go build -o /tmp/kydns ./cmd/kydns
mkdir -p /tmp/kydns-data
cat > /tmp/kydns-test.yaml <<'YAML'
data_dir: /tmp/kydns-data
dns:
  listen: "127.0.0.1:15353"
  allow_query: ["127.0.0.0/8"]
  upstreams: ["tls://1.1.1.1:853", "udp://192.0.2.1:53"]
admin:
  listen: "127.0.0.1:18053"
YAML
/tmp/kydns serve --config /tmp/kydns-test.yaml
```

In another shell, confirm the encrypted path actually resolves, then open
`http://127.0.0.1:18053` and check that the dashboard shows the plaintext
banner and Settings shows both upstreams with the right channel column:

```bash
dig @127.0.0.1 -p 15353 example.com A +short
```

Then confirm strict mode fails loudly with no reachable encrypted upstream:
change `upstreams` to `["tls://192.0.2.1:853"]`, restart, and check that
`dig @127.0.0.1 -p 15353 example.com A` returns SERVFAIL while Settings names
the timeout.

Clean up: `rm -rf /tmp/kydns-data /tmp/kydns-test.yaml /tmp/kydns`

- [ ] **Step 10: Commit**

```bash
gofmt -l . && go vet ./...
git add internal/web/ internal/app/serve.go
git commit -m "Show upstream transport and last error in the UI

A closed default is only safe if its failure mode is loud. Settings names
the upstream and the error, so a blocked port 853 reads as a firewall
rule rather than as broken DNS."
```

---

## Task 9: Documentation and the end-to-end check

**Files:**
- Modify: `README.md:30-49,69,86-98` — capabilities, settings table, a new section
- Modify: `.github/workflows/ci.yml` — resolve a public name over DoT

**Interfaces:**
- Consumes: everything above.
- Produces: nothing code depends on.

- [ ] **Step 1: Update the capability lists**

In `README.md`, under "What works today", replace the upstream line:

```markdown
- Upstream forwarding over DNS-over-TLS and DNS-over-HTTPS, with a cache,
  sequential failover, and single-flight.
```

Under "Not yet", delete the line *"DNS-over-TLS and DNS-over-HTTPS to upstreams.
Plain UDP and TCP only."* and add:

```markdown
- **Local DNSSEC validation.** KyDNS trusts the upstream's verdict over an
  encrypted channel; it does not verify signatures itself. An `AD` bit from
  KyDNS means "the resolver we talked to privately said it validated," not
  "KyDNS checked the chain."
```

- [ ] **Step 2: Update the settings table**

Replace the `dns.upstreams` row (line 69):

```markdown
| `dns.upstreams` | `tls://1.1.1.1:853`, `tls://9.9.9.9:853` | Tried in order. `tls://`, `https://`, or `udp://` before an **IP address**. See below. |
```

- [ ] **Step 3: Add the upstreams section**

Insert before the "### Tailscale" heading:

````markdown
### Upstream encryption

The scheme decides how much you trust the answer:

```yaml
dns:
  upstreams:
    - tls://1.1.1.1:853              # DNS-over-TLS
    - https://9.9.9.9/dns-query      # DNS-over-HTTPS
    - udp://192.168.1.1:53           # plain DNS, opted into per upstream
```

The host must be an **IP address**. A hostname would need DNS to resolve it,
and KyDNS may be the thing resolving — on a machine that points at itself that
is a loop. Cloudflare, Quad9 and Google all present certificates valid for
their IPs, so nothing further is needed. When a provider's certificate needs a
hostname, put it after a `#`:

```yaml
    - tls://45.90.28.0:853#abc123.dns.nextdns.io
```

That sets the TLS server name while still dialling the address you gave.
Certificate verification is always on and there is no option to turn it off.

**With only encrypted upstreams, a query fails rather than falling back.** If
every one is unreachable, clients get `SERVFAIL` and the Settings screen names
the upstream and the error — usually a firewall blocking port 853. That is the
intended behaviour: silently dropping to plain DNS is exactly what an attacker
who blocks 853 is hoping for.

The escape hatch is one line. Add a `udp://` upstream and KyDNS will use it
when the encrypted ones fail. Answers it serves have the authenticated-data
flag cleared, because nothing authenticated them, and the dashboard carries a
banner for as long as the entry is there.

KyDNS is not a validating resolver. It does not verify signatures, hold a trust
anchor, or walk a chain of trust. It makes the path to a resolver that does all
of that private and tamper-proof, and passes that resolver's verdict through.
````

- [ ] **Step 4: Add the CI check**

In `.github/workflows/ci.yml`, in the `docker` job, add a step after the
existing `dig` assertion in "image starts and serves DNS":

```yaml
      # The only check here that needs the internet. Everything else proves the
      # code is right against a fake; this proves it is right against
      # Cloudflare, over the tls:// default.
      - name: resolves a public name over DoT
        run: |
          set -eux
          answer=$(dig @127.0.0.1 -p 15353 example.com A +short)
          test -n "$answer" || {
            echo "no answer for example.com over DoT"
            docker logs kydns-ci
            exit 1; }
```

The container's config sets no `upstreams`, so it uses the `tls://` defaults.

- [ ] **Step 5: Verify the docs match the code**

Run: `go test ./internal/config/ -run TestExample -v`
Expected: PASS — the example config's documented values still equal the code's
defaults.

Read the README's settings table against `internal/web/settings.go`'s
`configRows` and confirm no row drifted.

- [ ] **Step 6: Commit**

```bash
git add README.md .github/workflows/ci.yml
git commit -m "Document encrypted upstreams and check DoT end to end

The README now says plainly what an AD bit from KyDNS does and does not
mean, so nobody reads it as local validation."
```

---

## Self-review

Checked against `docs/superpowers/specs/2026-08-14-kydns-encrypted-upstreams.md`:

| Spec section | Task |
|---|---|
| Part 1 — scheme grammar, ports, paths | 1 |
| Part 1 — IP-only host, bootstrap error | 1 |
| Part 1 — `#servername` for SNI, verified name, DoH URL | 1, 3, 4 |
| Part 1 — no `insecure_skip_verify` | 3 (`tlsConfig`), tested in 3 and 4 |
| Part 1 — defaults move to `tls://` | 7 |
| Part 2 — strict by construction | 6 (`TestForwarderAllUpstreamsDown`) |
| Part 2 — `CD=0`, `AD=1` outbound, `DO` forwarded | 5, 6 |
| Part 2 — `AD` cleared at the source | 6 |
| Part 2 — authoritative answers never carry `AD` | 6 |
| Part 3 — cache key gains `DO` | 5 |
| Part 4 — `internal/upstream` package, `Upstream` interface | 1, 2 |
| Part 4 — DoT connection pool with one retry | 3 |
| Part 4 — DoH via `net/http`, zeroed wire ID, limits | 4 |
| Part 4 — `Resolve(ctx, q, do)`, OPT stripped for plain clients | 5 |
| Part 5 — startup warning, dashboard banner, settings table | 6 (log), 8 (UI) |
| Part 6 — every listed test | 1–6, 8 |
| Part 7 — example config, README, CI DoT check | 7, 9 |

Type consistency: `UpstreamStatus` is defined once in Task 6 and consumed with
the same field names in Task 8. `Spec.RootCAs` is introduced in Task 1 and used
by `tlsConfig` in Task 3 and by both transport test files. `Upstream`'s three
methods are fixed in Task 2 and implemented unchanged in Tasks 2–4. `newForwarder`
changes shape once, in Task 6, and every call site in the package is listed there.
