package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busness-app/kydns-server/internal/upstream"
	"github.com/miekg/dns"
)

// fakeUpstream stands in for a real resolver. secure decides whether the AD
// bit it sets is allowed to survive.
type fakeUpstream struct {
	name   string
	secure bool
	calls  atomic.Int64
	delay  time.Duration
	reply  func(*dns.Msg) (*dns.Msg, error)
	closed atomic.Bool

	mu   sync.Mutex
	sent []*dns.Msg // queries as they went out
}

func (f *fakeUpstream) Secure() bool   { return f.secure }
func (f *fakeUpstream) String() string { return f.name }

func (f *fakeUpstream) Close() error {
	f.closed.Store(true)
	return nil
}

func (f *fakeUpstream) Exchange(_ context.Context, m *dns.Msg) (*dns.Msg, error) {
	f.calls.Add(1)
	f.mu.Lock()
	f.sent = append(f.sent, m.Copy())
	f.mu.Unlock()
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	resp, err := f.reply(m)
	// A real EDNS0 upstream echoes the DO bit in its reply; match that so
	// EDNS0 pass-through has something real to test.
	if resp != nil {
		if opt := m.IsEdns0(); opt != nil {
			resp.SetEdns0(opt.UDPSize(), opt.Do())
		}
	}
	return resp, err
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

// bigUpstream answers with roughly 2 KB of records, standing in for the
// DNSSEC-signed answers that RRSIGs push past a UDP datagram budget.
func bigUpstream(name string, secure bool) *fakeUpstream {
	return &fakeUpstream{name: name, secure: secure, reply: func(m *dns.Msg) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetReply(m)
		for i := 0; i < 10; i++ {
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name: m.Question[0].Name, Rrtype: dns.TypeTXT,
					Class: dns.ClassINET, Ttl: 300,
				},
				Txt: []string{strings.Repeat("x", 200)},
			})
		}
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

// Concurrent misses for the same name but different DO must not collapse
// into one leader: the singleflight key includes DO, so a DO=0 miss and a
// DO=1 miss stay two separate upstream queries instead of one leader handing
// its differently-shaped answer to the other's followers.
func TestForwarderSingleFlightSeparatesByDO(t *testing.T) {
	u := okUpstream("tls://1.1.1.1:853", true)
	u.delay = 50 * time.Millisecond
	f := newForwarder(u)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		do := i%2 == 0
		wg.Add(1)
		go func(do bool) {
			defer wg.Done()
			if _, err := f.Resolve(context.Background(), question("a.example.com."), do); err != nil {
				t.Error(err)
			}
		}(do)
	}
	wg.Wait()
	if got := u.calls.Load(); got != 2 {
		t.Errorf("upstream calls = %d, want exactly 2 (one per DO value)", got)
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

	// The recorded reason must not repeat the Spec column: Status.Spec
	// already names the upstream, so the UI would print it twice.
	dup := newForwarder(servfailUpstream("tls://6.6.6.6:853", true))
	if _, err := dup.Resolve(context.Background(), question("a.example.com."), false); err == nil {
		t.Fatal("Resolve() error = nil, want the single upstream's SERVFAIL to fail the query")
	}
	if got := dup.Status()[0].LastError; strings.Contains(got, "upstream ") {
		t.Errorf("Status()[0].LastError = %q, want no upstream-spec prefix", got)
	} else if got != "returned SERVFAIL" {
		t.Errorf("Status()[0].LastError = %q, want %q", got, "returned SERVFAIL")
	}

	// Recovery: a failure followed by success must not leave a stale
	// LastErrAt next to an empty LastError.
	flaky := &fakeUpstream{name: "tls://5.5.5.5:853", secure: true}
	attempts := 0
	flaky.reply = func(m *dns.Msg) (*dns.Msg, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("dial tcp: i/o timeout")
		}
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Answer = reply(m.Question[0].Name, 300).Answer
		return resp, nil
	}
	rf := newForwarder(flaky)
	if _, err := rf.Resolve(context.Background(), question("a.example.com."), false); err == nil {
		t.Fatal("Resolve() error = nil, want the first attempt to fail")
	}
	if _, err := rf.Resolve(context.Background(), question("b.example.com."), false); err != nil {
		t.Fatal(err)
	}
	rst := rf.Status()[0]
	if rst.LastError != "" {
		t.Errorf("recovered upstream LastError = %q, want empty after success", rst.LastError)
	}
	if !rst.LastErrAt.IsZero() {
		t.Errorf("recovered upstream LastErrAt = %v, want zero after success", rst.LastErrAt)
	}
	if rst.LastOKAt.IsZero() {
		t.Error("recovered upstream LastOKAt is zero after success")
	}
}

func TestForwarderReplace(t *testing.T) {
	a := okUpstream("udp://10.0.0.1:53", false)
	b := okUpstream("udp://10.0.0.2:53", false)

	f := newForwarder(a)
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
// entry. Each query targets a unique name so it actually reaches an upstream
// instead of being absorbed by the cache. The two-upstream list fails at
// index 0 and succeeds at index 1, so a record against index 1 lands out of
// range on the one-upstream list — a stale index does not just land on a
// different-but-valid entry, it panics. Meaningful only with -race.
func TestForwarderReplaceUnderLoad(t *testing.T) {
	a := okUpstream("udp://10.0.0.1:53", false)
	bad := deadUpstream("udp://10.0.0.2:53", false)
	good := okUpstream("udp://10.0.0.3:53", false)
	f := newForwarder(a)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			q := question(fmt.Sprintf("q%d.example.com.", i))
			_, _ = f.Resolve(context.Background(), q, false)
		}
	}()
	for i := 0; i < 500; i++ {
		if i%2 == 0 {
			f.Replace([]upstream.Upstream{bad, good})
		} else {
			f.Replace([]upstream.Upstream{a})
		}
		_ = f.Status()
	}
	<-done
}

// Replace must close only the upstreams it retires: an in-flight query still
// using the live ones must not have its connections pulled out from under it.
func TestForwarderReplaceClosesRetiredUpstreams(t *testing.T) {
	a := okUpstream("udp://10.0.0.1:53", false)
	b := okUpstream("udp://10.0.0.2:53", false)
	f := newForwarder(a)

	f.Replace([]upstream.Upstream{b})
	// The retired upstream's sockets must be released, not held until the
	// process exits. With no query in flight, wg is already zero, so this
	// resolves almost immediately rather than waiting out a timer.
	waitFor(t, 3*time.Second, func() bool { return a.closed.Load() })
	if b.closed.Load() {
		t.Error("Replace closed the live upstream, not just the retired one")
	}
}

// An upstream instance carried over unchanged into the new list (the shape a
// settings reload that only touches other fields would produce) must not be
// closed: its DoT pool is still live and in use.
func TestForwarderReplaceKeepsCarriedOverUpstream(t *testing.T) {
	a := okUpstream("udp://10.0.0.1:53", false)
	b := okUpstream("udp://10.0.0.2:53", false)
	f := newForwarder(a, b)

	f.Replace([]upstream.Upstream{b}) // a retired, b carried over unchanged
	waitFor(t, 3*time.Second, func() bool { return a.closed.Load() })
	if b.closed.Load() {
		t.Error("Replace closed an upstream instance still present in the new list")
	}
}

// Reproduces round-2 review finding 1: Replace(b) retires the state holding
// a and parks its retirement goroutine on that state's wg while a query is
// still in flight against a. Before that query finishes, Replace(a) brings a
// back as the live upstream. When the parked retirement goroutine finally
// wakes, it must check what is live *then*, not what it captured when it was
// scheduled — otherwise it closes an upstream that is live again.
func TestForwarderReplaceSkipsUpstreamMadeLiveAgainWhileRetiring(t *testing.T) {
	started := make(chan struct{})
	proceed := make(chan struct{})
	var startOnce sync.Once
	a := &fakeUpstream{name: "udp://10.0.0.1:53", reply: func(m *dns.Msg) (*dns.Msg, error) {
		startOnce.Do(func() { close(started) })
		<-proceed // closed proceed just falls through on any later call
		resp := new(dns.Msg)
		resp.SetReply(m)
		resp.Answer = reply(m.Question[0].Name, 300).Answer
		return resp, nil
	}}
	b := okUpstream("udp://10.0.0.2:53", false)
	f := newForwarder(a)

	resolveDone := make(chan struct{})
	go func() {
		defer close(resolveDone)
		_, _ = f.Resolve(context.Background(), question("a.example.com."), false)
	}()
	<-started // the exchange against a is in flight, holding the state it lives in

	f.Replace([]upstream.Upstream{b}) // retires the state holding a; its retirement goroutine parks on wg.Wait
	f.Replace([]upstream.Upstream{a}) // a is live again, in a new state

	close(proceed) // let the in-flight exchange finish, releasing the parked wg
	<-resolveDone

	// b's retirement (scheduled by the second Replace, with nothing to wait
	// on) completing gives a's earlier-scheduled retirement goroutine ample
	// time to run too.
	waitFor(t, 3*time.Second, func() bool { return b.closed.Load() })
	time.Sleep(50 * time.Millisecond) // settle window: proving an absence needs one

	if a.closed.Load() {
		t.Error("a pending retirement closed an upstream that was live again by the time it ran")
	}
	if _, err := f.Resolve(context.Background(), question("b.example.com."), false); err != nil {
		t.Fatalf("Resolve() after the sequence = %v, want the still-live upstream to answer", err)
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition never became true")
		}
		time.Sleep(time.Millisecond)
	}
}
