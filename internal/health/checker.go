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

	"github.com/Busness-app/kydns-server/internal/store"
)

// Failure and recovery thresholds: slow to alarm, fast to recover.
const (
	failuresToDown = 2
	successesToUp  = 1

	StateUp      = "up"
	StateDown    = "down"
	StateUnknown = "unknown"
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
	status    Status
	failures  int
	successes int
}

type Checker struct {
	lister Lister
	logger *slog.Logger
	now    func() time.Time

	cfgMu    sync.RWMutex
	interval time.Duration
	timeout  time.Duration
	workers  int
	changed  chan struct{} // buffered 1; wakes a Run blocked on the old interval

	mu      sync.RWMutex
	entries map[int64]*entry
}

func NewChecker(lister Lister, interval, timeout time.Duration, workers int, logger *slog.Logger) *Checker {
	if logger == nil {
		logger = slog.Default()
	}
	c := &Checker{lister: lister, logger: logger, now: time.Now, entries: map[int64]*entry{}, changed: make(chan struct{}, 1)}
	c.Reconfigure(interval, timeout, workers)
	// Reconfigure queues a wake token, but a brand-new Checker has no Run in
	// flight to wake. Drain it so the first Run doesn't see a stale token and
	// double its startup cycle.
	select {
	case <-c.changed:
	default:
	}
	return c
}

// minInterval is the floor for the probe schedule. Zero or negative would
// turn Run's timer into a hot spin (time.NewTicker(0) used to panic loudly;
// a Reset(0) instead spins silently). It only guards against that failure
// mode — sane production minimums are the settings validator's job.
const minInterval = time.Millisecond

// Reconfigure changes the probe schedule. A change takes effect immediately:
// a Run already in flight picks up the new interval and runs a probe cycle
// right away rather than waiting out the old interval or the next restart.
func (c *Checker) Reconfigure(interval, timeout time.Duration, workers int) {
	if workers < 1 {
		workers = 8
	}
	if interval < minInterval {
		interval = minInterval
	}
	c.cfgMu.Lock()
	c.interval, c.timeout, c.workers = interval, timeout, workers
	c.cfgMu.Unlock()
	select {
	case c.changed <- struct{}{}:
	default:
	}
}

// Config returns the live schedule.
func (c *Checker) Config() (interval, timeout time.Duration, workers int) {
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()
	return c.interval, c.timeout, c.workers
}

func (c *Checker) Run(ctx context.Context) {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		c.CheckOnce(ctx)
		interval, _, _ := c.Config()
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(interval)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-c.changed:
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

	_, _, workers := c.Config()
	jobs := make(chan store.Service)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
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
		c.record(svc, StateUnknown, nil)
		return
	}
	c.record(svc, "", c.probe(ctx, svc.CheckURL, svc.CheckInsecure))
}

// record applies the hysteresis and logs transitions only, not every probe.
func (c *Checker) record(svc store.Service, forced string, probeErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[svc.ID]
	if !ok {
		e = &entry{status: Status{ServiceID: svc.ID, State: StateUnknown, Since: c.now()}}
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
			e.status.State = StateUp
		}
	default:
		e.failures++
		e.successes = 0
		e.status.LastError = probeErr.Error()
		if e.failures >= failuresToDown {
			e.status.State = StateDown
		}
	}

	if e.status.State != previous {
		e.status.Since = c.now()
		c.logger.Info("service health changed",
			"service", svc.Name, "from", previous, "to", e.status.State,
			"error", e.status.LastError)
	}
}

// probe supports http(s) and tcp. For HTTP a 2xx or 3xx is healthy and
// redirects are not followed; for tcp a completed connection is healthy and
// nothing is read or written.
func (c *Checker) probe(ctx context.Context, target string, insecure bool) error {
	_, timeout, _ := c.Config()
	ctx, cancel := context.WithTimeout(ctx, timeout)
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
