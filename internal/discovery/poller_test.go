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
