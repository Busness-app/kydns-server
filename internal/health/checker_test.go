package health

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busness-app/kydns-server/internal/store"
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
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // nothing listens now

	c := newChecker([]store.Service{{ID: 1, Name: "tcp-down", CheckURL: "tcp://" + addr}})
	c.CheckOnce(context.Background())
	c.CheckOnce(context.Background())
	if got := statusOf(t, c, "tcp-down").State; got != "down" {
		t.Errorf("State = %q, want down", got)
	}
	if statusOf(t, c, "tcp-down").LastError == "" {
		t.Error("LastError is empty for a down service")
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

// Since advances only on a transition, so "down since" is meaningful.
func TestSinceOnlyMovesOnTransition(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newChecker([]store.Service{{ID: 1, Name: "steady", CheckURL: srv.URL}})
	c.CheckOnce(context.Background())
	first := statusOf(t, c, "steady").Since
	time.Sleep(10 * time.Millisecond)
	c.CheckOnce(context.Background())
	if got := statusOf(t, c, "steady").Since; !got.Equal(first) {
		t.Errorf("Since moved without a state change: %v then %v", first, got)
	}
}

// Many services must not spawn one goroutine each.
func TestBoundedWorkerPool(t *testing.T) {
	var inFlight, peak atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var svcs []store.Service
	for i := 0; i < 30; i++ {
		svcs = append(svcs, store.Service{ID: int64(i + 1), Name: "svc", CheckURL: srv.URL})
	}
	c := NewChecker(&fakeLister{svcs: svcs}, time.Minute, 2*time.Second, 4, nil)
	c.CheckOnce(context.Background())
	if peak.Load() > 4 {
		t.Errorf("peak concurrent probes = %d, want at most the 4 configured workers", peak.Load())
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
	case <-time.After(3 * time.Second):
		t.Fatal("Run() did not return after cancellation")
	}
}

func TestCheckerReconfigure(t *testing.T) {
	c := NewChecker(&fakeLister{}, 30*time.Second, 5*time.Second, 8, slog.Default())
	c.Reconfigure(10*time.Second, 2*time.Second, 3)

	i, to, w := c.Config()
	if i != 10*time.Second || to != 2*time.Second || w != 3 {
		t.Errorf("got %v/%v/%d, want 10s/2s/3", i, to, w)
	}
}

// Zero workers would mean no probes ever run, so the floor NewChecker applies
// has to apply here too.
func TestCheckerReconfigureFloorsWorkers(t *testing.T) {
	c := NewChecker(&fakeLister{}, 30*time.Second, 5*time.Second, 8, slog.Default())
	c.Reconfigure(10*time.Second, 2*time.Second, 0)
	if _, _, w := c.Config(); w < 1 {
		t.Errorf("workers dropped to %d, which would stop every probe", w)
	}
}

// A shortened interval must be observed by a Run already in flight, not only
// after a restart.
func TestCheckerRunObservesNewInterval(t *testing.T) {
	lister := &countingLister{}
	c := NewChecker(lister, time.Hour, time.Second, 1, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	waitFor(t, func() bool { return lister.Calls() >= 1 }) // the immediate first cycle
	c.Reconfigure(5*time.Millisecond, time.Millisecond, 1)
	waitFor(t, func() bool { return lister.Calls() >= 3 })
}

// A zero or negative interval must not turn Run's timer into a hot spin.
func TestCheckerReconfigureFloorsInterval(t *testing.T) {
	c := NewChecker(&fakeLister{}, 30*time.Second, 5*time.Second, 8, slog.Default())
	c.Reconfigure(0, time.Second, 1)
	if i, _, _ := c.Config(); i <= 0 {
		t.Errorf("interval floored to %v, want a positive duration", i)
	}
}

// NewChecker must not leave a wake token queued: Reconfigure queues one, but
// a brand-new Checker has no Run in flight yet, so the first Run must not
// see it as a second startup cycle.
func TestNewCheckerRunsExactlyOneStartupCycle(t *testing.T) {
	lister := &countingLister{}
	c := NewChecker(lister, time.Hour, time.Second, 1, slog.Default())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	c.Run(ctx)

	if calls := lister.Calls(); calls != 1 {
		t.Errorf("Run() did %d cycles at startup, want exactly 1", calls)
	}
}

type countingLister struct {
	mu sync.Mutex
	n  int
}

func (c *countingLister) Services() ([]store.Service, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return nil, nil
}

func (c *countingLister) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within two seconds")
}
