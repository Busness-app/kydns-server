package replica

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// staleAfter is how long without a successful poll before the operator
// surface calls this replica stale. Twelve missed ticks at the 5s interval.
const staleAfter = 60 * time.Second

// Primary is the half of Client the pull loop uses. It is an interface so the
// loop can be tested without a socket; *Client is the only real implementation.
type Primary interface {
	Version(ctx context.Context) (VersionReply, error)
	Snapshot(ctx context.Context) (Snapshot, error)
	Close() error
}

// Applier writes a pulled configuration.
type Applier interface {
	// Apply decodes a snapshot's Config and writes it in one transaction.
	Apply(cfg json.RawMessage) error
}

// StateStore persists the primary's version so a restarted replica does not
// re-pull a configuration it already holds.
type StateStore interface {
	ReplicaState() (primaryNodeID string, version int64, err error)
	SetReplicaState(primaryNodeID string, version int64) error
}

// SnapshotApplier applies a pulled document to the local store. ApplySnapshot
// keeps the node-local settings itself, so nothing is merged here.
type SnapshotApplier struct {
	Store interface {
		ApplySnapshot(in store.SnapshotInput) error
	}
}

func (a SnapshotApplier) Apply(cfg json.RawMessage) error {
	var in store.SnapshotInput
	if err := json.Unmarshal(cfg, &in); err != nil {
		return fmt.Errorf("decode snapshot: %w", err)
	}
	return a.Store.ApplySnapshot(in)
}

// Status is what the operator surface renders.
type Status struct {
	PrimaryNodeID string
	LastSyncAt    time.Time
	LastVersion   int64
	LastError     string
	Stale         bool
}

// Puller polls one primary and applies what changed. Every failure mode leaves
// the last good configuration serving: the loop goes stale, never broken.
type Puller struct {
	dial     func(ctx context.Context) (Primary, error)
	ap       Applier
	state    StateStore
	interval time.Duration
	ceiling  time.Duration
	now      func() time.Time

	mu          sync.Mutex
	primaryID   string
	lastVersion int64
	lastSyncAt  time.Time
	lastErr     string
	backoff     time.Duration
}

func NewPuller(dial func(context.Context) (Primary, error), ap Applier,
	state StateStore, interval, ceiling time.Duration, now func() time.Time) *Puller {
	p := &Puller{dial: dial, ap: ap, state: state, interval: interval,
		ceiling: ceiling, now: now, backoff: interval}
	nodeID, version, err := state.ReplicaState()
	if err != nil {
		// Unreadable bookkeeping costs a redundant apply, not a refusal to run.
		p.lastErr = err.Error()
	}
	p.primaryID, p.lastVersion = nodeID, version
	return p
}

func (p *Puller) Run(ctx context.Context) {
	t := time.NewTimer(p.wait())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		p.poll(ctx)
		t.Reset(p.wait())
	}
}

// poll is one tick. It returns on every error rather than propagating one,
// because an unreachable primary is an ordinary state on a home network.
func (p *Puller) poll(ctx context.Context) {
	c, err := p.dial(ctx)
	if err != nil {
		p.unreachable(err)
		return
	}
	defer c.Close()

	v, err := c.Version(ctx)
	if err != nil {
		p.unreachable(err)
		return
	}
	p.reachable()

	if v.SchemaVersion != SchemaVersion {
		p.fail(fmt.Errorf("primary %s speaks replication schema %d, this node speaks %d: upgrade the older node",
			v.NodeID, v.SchemaVersion, SchemaVersion))
		return
	}
	if v.ConfigVersion == p.held() {
		p.synced(v.NodeID, v.ConfigVersion)
		return
	}

	snap, err := c.Snapshot(ctx)
	if err != nil {
		p.fail(err)
		return
	}
	if snap.SchemaVersion != SchemaVersion {
		p.fail(fmt.Errorf("primary %s speaks replication schema %d, this node speaks %d: upgrade the older node",
			snap.NodeID, snap.SchemaVersion, SchemaVersion))
		return
	}
	// A failed apply leaves lastVersion alone so the next tick retries.
	if err := p.ap.Apply(snap.Config); err != nil {
		p.fail(fmt.Errorf("apply version %d: %w", snap.ConfigVersion, err))
		return
	}
	if err := p.state.SetReplicaState(snap.NodeID, snap.ConfigVersion); err != nil {
		// The configuration landed but the bookkeeping did not, so the next
		// tick applies the same version again rather than claiming it is held.
		p.fail(err)
		return
	}
	p.synced(snap.NodeID, snap.ConfigVersion)
}

func (p *Puller) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Status{
		PrimaryNodeID: p.primaryID,
		LastSyncAt:    p.lastSyncAt,
		LastVersion:   p.lastVersion,
		LastError:     p.lastErr,
		Stale:         p.now().Sub(p.lastSyncAt) > staleAfter,
	}
}

// wait is how long until the next tick: the interval, or the current backoff
// while the primary is unreachable.
func (p *Puller) wait() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.backoff
}

// held is the primary version this replica has already applied.
func (p *Puller) held() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastVersion
}

func (p *Puller) unreachable(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastErr = err.Error()
	p.backoff *= 2
	if p.backoff > p.ceiling {
		p.backoff = p.ceiling
	}
}

// reachable resets the backoff. The primary answered, so whatever happens next
// is a document problem, not a network one, and retrying slowly will not help.
func (p *Puller) reachable() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.backoff = p.interval
}

func (p *Puller) fail(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastErr = err.Error()
}

func (p *Puller) synced(primaryID string, version int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.primaryID, p.lastVersion, p.lastSyncAt = primaryID, version, p.now()
	p.lastErr = ""
}
