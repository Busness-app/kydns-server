package dnsserver

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/upstream"
)

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
}
