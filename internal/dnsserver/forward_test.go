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
		// SetReply resets Rcode, so restore whatever the case under test set.
		rcode := resp.Rcode
		resp.SetReply(m)
		resp.Rcode = rcode
		if rcode == dns.RcodeSuccess {
			resp.Answer = reply(m.Question[0].Name, 300).Answer
		}
	}
	return resp, err
}

func okReply() (*dns.Msg, error) { return new(dns.Msg), nil }

func failReply() (*dns.Msg, error) { return nil, errors.New("timeout") }

func newForwarder(x Exchanger, upstreams ...string) *Forwarder {
	return NewForwarder(upstreams, time.Second, NewCache(10, 5, 3600, 300), x)
}

func TestForwarderUsesFirstWorkingUpstream(t *testing.T) {
	x := &fakeExchanger{perAddr: map[string]func() (*dns.Msg, error){
		"1.1.1.1:53": failReply,
		"9.9.9.9:53": okReply,
	}}
	f := newForwarder(x, "1.1.1.1:53", "9.9.9.9:53")
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
	f := newForwarder(x, "1.1.1.1:53", "9.9.9.9:53")
	if _, err := f.Resolve(context.Background(), question("a.example.com.")); err == nil {
		t.Fatal("Resolve() error = nil, want an error when every upstream fails")
	}
}

func TestForwarderNoUpstreamsConfigured(t *testing.T) {
	f := newForwarder(&fakeExchanger{perAddr: map[string]func() (*dns.Msg, error){}})
	if _, err := f.Resolve(context.Background(), question("a.example.com.")); err == nil {
		t.Error("Resolve() error = nil with no upstreams, want an error")
	}
}

func TestForwarderServesFromCache(t *testing.T) {
	x := &fakeExchanger{perAddr: map[string]func() (*dns.Msg, error){"1.1.1.1:53": okReply}}
	f := newForwarder(x, "1.1.1.1:53")
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
	f := newForwarder(x, "1.1.1.1:53")

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

// A SERVFAIL from one upstream must fail over rather than be returned.
func TestForwarderFailsOverOnServfail(t *testing.T) {
	servfail := func() (*dns.Msg, error) {
		m := new(dns.Msg)
		m.Rcode = dns.RcodeServerFailure
		return m, nil
	}
	x := &fakeExchanger{perAddr: map[string]func() (*dns.Msg, error){
		"1.1.1.1:53": servfail,
		"9.9.9.9:53": okReply,
	}}
	f := newForwarder(x, "1.1.1.1:53", "9.9.9.9:53")
	if _, err := f.Resolve(context.Background(), question("a.example.com.")); err != nil {
		t.Fatalf("Resolve() = %v, want failover to the healthy upstream", err)
	}
	if got := x.calls.Load(); got != 2 {
		t.Errorf("upstream calls = %d, want 2", got)
	}
}

func TestForwarderUpstreams(t *testing.T) {
	f := newForwarder(&fakeExchanger{}, "1.1.1.1:53", "9.9.9.9:53")
	if got := f.Upstreams(); len(got) != 2 {
		t.Errorf("Upstreams() = %v", got)
	}
}
