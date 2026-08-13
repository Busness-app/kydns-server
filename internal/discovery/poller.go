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
	onChange func()
	logger   *slog.Logger

	cfgMu    sync.RWMutex
	interval time.Duration
	changed  chan struct{} // buffered 1; wakes a Run blocked on the old interval

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
	p := &Poller{src: src, onChange: onChange, logger: logger, changed: make(chan struct{}, 1)}
	p.SetInterval(interval)
	// SetInterval queues a wake token, but a brand-new Poller has no Run in
	// flight to wake. Drain it so the first Run doesn't see a stale token and
	// double its startup cycle.
	select {
	case <-p.changed:
	default:
	}
	return p
}

// minInterval is the floor for the poll schedule. Zero or negative would turn
// Run's timer into a hot spin. It only guards against that failure mode —
// sane production minimums are the settings validator's job.
const minInterval = time.Millisecond

// SetInterval changes the poll cadence. A change takes effect immediately: a
// Run already in flight picks up the new interval and polls right away
// rather than waiting out the old interval or the next restart.
func (p *Poller) SetInterval(d time.Duration) {
	if d < minInterval {
		d = minInterval
	}
	p.cfgMu.Lock()
	p.interval = d
	p.cfgMu.Unlock()
	select {
	case p.changed <- struct{}{}:
	default:
	}
}

func (p *Poller) Interval() time.Duration {
	p.cfgMu.RLock()
	defer p.cfgMu.RUnlock()
	return p.interval
}

// Run polls until ctx is cancelled, starting with an immediate cycle so the
// first snapshot does not wait a full interval.
func (p *Poller) Run(ctx context.Context) {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		if err := p.Poll(ctx); err != nil {
			p.logger.Warn("lease poll failed, keeping the last known leases",
				"source", p.src.Name(), "error", err)
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(p.Interval())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-p.changed:
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
		if s, ok := p.src.(interface{ Skipped() []string }); ok {
			for _, reason := range s.Skipped() {
				p.logger.Warn("lease skipped", "source", p.src.Name(), "reason", reason)
			}
		}
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
