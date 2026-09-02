package discovery

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/Busness-app/kydns-server/internal/discovery/dhcp"
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

func (f *fakeSource) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
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

// A lease disappearing is a change too.
func TestPollDetectsRemoval(t *testing.T) {
	src := &fakeSource{leases: []dhcp.Lease{
		{Hostname: "a", IP: "192.168.1.1"}, {Hostname: "b", IP: "192.168.1.2"},
	}}
	var changes int
	p := NewPoller(src, time.Minute, func() { changes++ }, nil)
	p.Poll(context.Background())

	src.set([]dhcp.Lease{{Hostname: "a", IP: "192.168.1.1"}}, nil)
	p.Poll(context.Background())
	if changes != 2 {
		t.Errorf("onChange called %d times, want 2 after a lease disappeared", changes)
	}
	if got := p.Leases(); len(got) != 1 {
		t.Errorf("Leases() = %+v, want one", got)
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

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run() did not return after the context was cancelled")
	}
	if calls := src.callCount(); calls < 2 {
		t.Errorf("source polled %d times, want repeated polling", calls)
	}
}

// Run polls immediately so the first snapshot does not wait a full interval.
func TestRunPollsImmediately(t *testing.T) {
	src := &fakeSource{leases: []dhcp.Lease{{Hostname: "a", IP: "192.168.1.1"}}}
	p := NewPoller(src, time.Hour, func() {}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	p.Run(ctx)

	if len(p.Leases()) != 1 {
		t.Error("Run() did not poll before its first tick")
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

func TestPollerConcurrentReads(t *testing.T) {
	src := &fakeSource{leases: []dhcp.Lease{{Hostname: "a", IP: "192.168.1.1"}}}
	p := NewPoller(src, time.Minute, func() {}, nil)
	p.Poll(context.Background())

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if len(p.Leases()) != 1 {
					t.Error("reader saw an inconsistent lease set")
					return
				}
			}
		}()
	}
	for j := 0; j < 50; j++ {
		p.Poll(context.Background())
	}
	wg.Wait()
}

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

// A zero or negative interval must not turn Run's timer into a hot spin.
func TestPollerSetIntervalFloorsInterval(t *testing.T) {
	p := NewPoller(&countingSource{}, time.Hour, nil, slog.Default())
	p.SetInterval(0)
	if got := p.Interval(); got <= 0 {
		t.Errorf("interval floored to %v, want a positive duration", got)
	}
}

// NewPoller must not leave a wake token queued: SetInterval queues one, but
// a brand-new Poller has no Run in flight yet, so the first Run must not
// see it as a second startup cycle.
func TestNewPollerRunsExactlyOneStartupCycle(t *testing.T) {
	src := &countingSource{}
	p := NewPoller(src, time.Hour, nil, slog.Default())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	p.Run(ctx)

	if calls := src.Calls(); calls != 1 {
		t.Errorf("Run() did %d cycles at startup, want exactly 1", calls)
	}
}

type countingSource struct {
	mu sync.Mutex
	n  int
}

func (c *countingSource) Name() string { return "counting" }

func (c *countingSource) Leases(context.Context) ([]dhcp.Lease, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return nil, nil
}

func (c *countingSource) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func waitForPolls(t *testing.T, src *countingSource, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if src.Calls() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within two seconds")
}

type namedSource struct {
	name   string
	leases []dhcp.Lease
}

func (s *namedSource) Leases(context.Context) ([]dhcp.Lease, error) { return s.leases, nil }
func (s *namedSource) Name() string                                 { return s.name }

func TestSetSourceSwapsWithoutRestart(t *testing.T) {
	a := &namedSource{name: "a", leases: []dhcp.Lease{{MAC: "aa", IP: "192.168.1.10", Hostname: "one"}}}
	b := &namedSource{name: "b", leases: []dhcp.Lease{{MAC: "bb", IP: "192.168.1.11", Hostname: "two"}}}

	p := NewPoller(a, time.Hour, func() {}, slog.New(slog.DiscardHandler))
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if got := p.Leases(); len(got) != 1 || got[0].Hostname != "one" {
		t.Fatalf("before swap = %+v, want the source-a lease", got)
	}

	p.SetSource(b)
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if got := p.Leases(); len(got) != 1 || got[0].Hostname != "two" {
		t.Fatalf("after swap = %+v, want the source-b lease", got)
	}
}

func TestNilSourceRetiresPublishedLeases(t *testing.T) {
	changed := 0
	p := NewPoller(
		&namedSource{name: "a", leases: []dhcp.Lease{{MAC: "aa", IP: "192.168.1.10", Hostname: "one"}}},
		time.Hour, func() { changed++ }, slog.New(slog.DiscardHandler))
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if changed != 1 {
		t.Fatalf("onChange called %d times after the first poll, want 1", changed)
	}

	p.SetSource(nil)
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("poll with no source: %v", err)
	}
	if got := p.Leases(); len(got) != 0 {
		t.Fatalf("leases after clearing the source = %+v, want none", got)
	}
	if changed != 2 {
		t.Fatalf("onChange called %d times, want 2: retiring every lease is a change", changed)
	}
}

func TestNewPollerToleratesNilSource(t *testing.T) {
	p := NewPoller(nil, time.Hour, func() {}, slog.New(slog.DiscardHandler))
	if err := p.Poll(context.Background()); err != nil {
		t.Fatalf("poll with no source: %v", err)
	}
	if got := p.Leases(); len(got) != 0 {
		t.Fatalf("leases = %+v, want none", got)
	}
}

// SetSource is driven from a different goroutine than Poll and Run in production,
// so a concurrent test ensures the lock actually protects both call sites.
func TestSetSourceConcurrentWithRun(t *testing.T) {
	srcA := &namedSource{name: "a", leases: []dhcp.Lease{{MAC: "aa", IP: "192.168.1.1", Hostname: "host-a"}}}
	srcB := &namedSource{name: "b", leases: []dhcp.Lease{{MAC: "bb", IP: "192.168.1.2", Hostname: "host-b"}}}
	srcC := &namedSource{name: "c", leases: []dhcp.Lease{{MAC: "cc", IP: "192.168.1.3", Hostname: "host-c"}}}

	changed := make(chan struct{}, 10) // buffered so onChange doesn't block
	p := NewPoller(srcA, 5*time.Millisecond, func() { changed <- struct{}{} }, slog.New(slog.DiscardHandler))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	// Wait for the initial poll to complete.
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("initial poll did not complete in time")
	}

	// Swap to source B while Run is polling.
	p.SetSource(srcB)
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("poll after swap to B did not complete in time")
	}

	// Swap to nil to retire all leases.
	p.SetSource(nil)
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("poll after swap to nil did not complete in time")
	}

	// Verify the final state reflects the nil source.
	leases := p.Leases()
	if len(leases) != 0 {
		t.Errorf("Leases() = %+v after nil swap, want empty", leases)
	}

	// Swap back to source C to verify recovery.
	p.SetSource(srcC)
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("poll after swap to C did not complete in time")
	}

	leases = p.Leases()
	if len(leases) != 1 || leases[0].Hostname != "host-c" {
		t.Errorf("Leases() = %+v after swap to C, want host-c", leases)
	}

	cancel()
}
