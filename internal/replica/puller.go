package replica

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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
	// Version reports the primary's version and tells it which version this
	// replica holds, which is what the primary records as this peer's lag.
	Version(ctx context.Context, held int64) (VersionReply, error)
	Snapshot(ctx context.Context) (Snapshot, error)
	// HealthStatus reports current service health, keyed by service name.
	HealthStatus(ctx context.Context) (map[string]string, error)
	Close() error
}

// healthUnknownState is what an unreachable or rejecting primary answers with
// for every service this replica last held health for. A stale value would
// tell an operator a dead service is alive during the one moment that matters.
const healthUnknownState = "unknown"

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

// PullerConfig is everything one pull loop needs. Pinned is the fingerprint
// the operator approved, and it is the only key this loop will ever follow.
type PullerConfig struct {
	Dial     func(ctx context.Context) (Primary, error)
	Pinned   string
	Apply    Applier
	State    StateStore
	Interval time.Duration
	Ceiling  time.Duration
	Now      func() time.Time
	Logger   *slog.Logger
}

// Puller polls one primary and applies what changed. Every failure mode leaves
// the last good configuration serving: the loop goes stale, never broken.
type Puller struct {
	cfg PullerConfig

	// conn is held across ticks so a poll costs one request rather than a fresh
	// TLS handshake. Only poll touches it, and poll runs on one goroutine.
	conn Primary

	mu          sync.Mutex
	lastVersion int64
	lastSyncAt  time.Time
	lastErr     string
	backoff     time.Duration
	// health is the last health reply received. healthKnown false means the
	// primary is unreachable or rejected the last poll, so Health() answers
	// unknown for every key here rather than the last value seen.
	health      map[string]string
	healthKnown bool
}

func NewPuller(cfg PullerConfig) *Puller {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	p := &Puller{cfg: cfg, backoff: cfg.Interval}
	nodeID, version, err := cfg.State.ReplicaState()
	if err != nil {
		// Unreadable bookkeeping costs a redundant apply, not a refusal to run.
		p.lastErr = err.Error()
	}
	// A state row naming a different primary is bookkeeping for a peer this loop
	// is not following, so the version in it says nothing about what is held.
	if nodeID == cfg.Pinned {
		p.lastVersion = version
	}
	return p
}

func (p *Puller) Run(ctx context.Context) {
	t := time.NewTimer(p.wait())
	defer t.Stop()
	defer p.drop()
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
	c, err := p.connect(ctx)
	if err != nil {
		p.unreachable(err)
		p.healthUnknown()
		return
	}

	v, err := c.Version(ctx, p.held())
	if err != nil {
		p.drop()
		p.unreachable(err)
		p.healthUnknown()
		return
	}

	// The transition to reachable waits for the node ID check: a peer that
	// answers with the wrong key has rejected the pin, and resetting the
	// backoff for that reply would hold the loop at the plain interval
	// instead of backing off from a peer that keeps failing identity.
	if err := p.checkNodeID(v.NodeID); err != nil {
		p.drop()
		p.reject(err)
		p.healthUnknown()
		return
	}
	p.reachable()

	if v.SchemaVersion != SchemaVersion {
		p.fail(fmt.Errorf("primary %s speaks replication schema %d, this node speaks %d: upgrade the older node",
			v.NodeID, v.SchemaVersion, SchemaVersion))
		p.healthUnknown()
		return
	}

	// Health rides this same tick but is its own request: it must never move
	// config_version or trigger a snapshot pull.
	p.pollHealth(ctx, c)

	if v.ConfigVersion == p.held() {
		p.synced(v.ConfigVersion)
		return
	}

	snap, err := c.Snapshot(ctx)
	if err != nil {
		p.drop()
		p.fail(err)
		return
	}
	if err := p.checkNodeID(snap.NodeID); err != nil {
		p.drop()
		p.fail(err)
		return
	}
	if snap.SchemaVersion != SchemaVersion {
		p.fail(fmt.Errorf("primary %s speaks replication schema %d, this node speaks %d: upgrade the older node",
			snap.NodeID, snap.SchemaVersion, SchemaVersion))
		return
	}
	// A failed apply leaves lastVersion alone so the next tick retries.
	if err := p.cfg.Apply.Apply(snap.Config); err != nil {
		p.fail(fmt.Errorf("apply version %d: %w", snap.ConfigVersion, err))
		return
	}
	// The pin is what is recorded, never what the reply claimed: a primary held
	// for one poll must not be able to leave its own key pinned behind it.
	if err := p.cfg.State.SetReplicaState(p.cfg.Pinned, snap.ConfigVersion); err != nil {
		// The configuration landed but the bookkeeping did not, so the next
		// tick applies the same version again rather than claiming it is held.
		p.fail(err)
		return
	}
	p.synced(snap.ConfigVersion)
}

// checkNodeID refuses a reply that names a key other than the one the
// handshake proved. The transport already pinned the connection; this closes
// the body, which is not evidence of anything.
func (p *Puller) checkNodeID(got string) error {
	if got == p.cfg.Pinned {
		return nil
	}
	return fmt.Errorf("primary claims node %q but this node is pinned to %s", got, p.cfg.Pinned)
}

func (p *Puller) connect(ctx context.Context) (Primary, error) {
	if p.conn != nil {
		return p.conn, nil
	}
	c, err := p.cfg.Dial(ctx)
	if err != nil {
		return nil, err
	}
	p.conn = c
	return c, nil
}

// drop throws the connection away so the next tick builds a fresh one.
func (p *Puller) drop() {
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
}

func (p *Puller) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Status{
		PrimaryNodeID: p.cfg.Pinned,
		LastSyncAt:    p.lastSyncAt,
		LastVersion:   p.lastVersion,
		LastError:     p.lastErr,
		Stale:         p.cfg.Now().Sub(p.lastSyncAt) > staleAfter,
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

// pollHealth fetches health and replaces what is held. A fetch error marks
// health unknown without touching the sync state: the config side of the poll
// already succeeded and must not be undone by a health-only failure.
func (p *Puller) pollHealth(ctx context.Context, c Primary) {
	statuses, err := c.HealthStatus(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.healthKnown = false
		return
	}
	p.health, p.healthKnown = statuses, true
}

// healthUnknown marks health stale without discarding the key set, so Health()
// answers unknown for every service this replica has previously heard about.
// Before the first successful poll there is no key set yet, and Health()
// answers empty either way — that is a cold start, not stale data.
func (p *Puller) healthUnknown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.healthKnown = false
}

// Health is what the operator surface renders for service status. An
// unreachable or rejecting primary answers unknown for every key, never the
// last value seen: stale-but-green health is worse than no answer at all.
func (p *Puller) Health() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]string, len(p.health))
	for k, v := range p.health {
		if !p.healthKnown {
			v = healthUnknownState
		}
		out[k] = v
	}
	return out
}

func (p *Puller) unreachable(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.record(err, slog.LevelWarn)
	p.backoff *= 2
	if p.backoff > p.cfg.Ceiling {
		p.backoff = p.cfg.Ceiling
	}
}

// reachable resets the backoff. The primary answered, so whatever happens next
// is a document problem, not a network one, and retrying slowly will not help.
func (p *Puller) reachable() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.backoff = p.cfg.Interval
}

func (p *Puller) fail(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.record(err, slog.LevelError)
}

// reject is fail plus a backoff: the network answered, so this is not the
// ordinary unreachable case, but the reply itself was refused, and retrying
// at the plain interval would just get rejected again.
func (p *Puller) reject(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.record(err, slog.LevelError)
	p.backoff *= 2
	if p.backoff > p.cfg.Ceiling {
		p.backoff = p.cfg.Ceiling
	}
}

// record logs only when the reason changes, so a primary that is down all
// night is one line rather than one line every five seconds.
func (p *Puller) record(err error, level slog.Level) {
	msg := err.Error()
	if msg != p.lastErr {
		p.cfg.Logger.Log(context.Background(), level, "replication failing",
			"primary_node_id", p.cfg.Pinned, "error", msg)
	}
	p.lastErr = msg
}

func (p *Puller) synced(version int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastErr != "" {
		p.cfg.Logger.Info("replication recovered", "primary_node_id", p.cfg.Pinned, "version", version)
	}
	p.lastVersion, p.lastSyncAt = version, p.cfg.Now()
	p.lastErr = ""
}
