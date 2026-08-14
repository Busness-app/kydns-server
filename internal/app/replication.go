package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/adminapi"
	"github.com/yoshiofthewire/kydns-server/internal/config"
	"github.com/yoshiofthewire/kydns-server/internal/health"
	"github.com/yoshiofthewire/kydns-server/internal/policy"
	"github.com/yoshiofthewire/kydns-server/internal/replica"
	"github.com/yoshiofthewire/kydns-server/internal/settings"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

const (
	// pullInterval is how often a replica asks its primary for a version. The
	// question is two numbers wide and almost always answered "nothing changed".
	pullInterval = 5 * time.Second
	// pullCeiling bounds the backoff while a primary is unreachable, so a
	// primary that comes back is followed again within a minute.
	pullCeiling = time.Minute
	// inviteTTL is how long a pairing code an operator is reading off one screen
	// stays good for.
	inviteTTL = 10 * time.Minute
)

// storeSource is the primary's half: what a replica pulls.
type storeSource struct {
	st     *store.Store
	nodeID string
	// health reads the checker's live results. It is a func, not a stored
	// snapshot, because health changes constantly and must be read fresh on
	// every request, never cached alongside config_version.
	health func() []health.Status
}

// The replication wire vocabulary, defined once: both halves of the
// translation are in this file, and two spellings of "unhealthy" would be a
// dead service showing as unknown on every replica.
const (
	wireHealthy   = "healthy"
	wireUnhealthy = "unhealthy"
	wireUnknown   = "unknown"
)

// HealthStatus translates the checker's up/down/unknown into the replication
// wire vocabulary, keyed by service name since a replica has no service IDs
// to match against. A nil health func (no checker wired) answers empty.
func (s *storeSource) HealthStatus() (map[string]string, error) {
	if s.health == nil {
		return map[string]string{}, nil
	}
	statuses := s.health()
	out := make(map[string]string, len(statuses))
	for _, st := range statuses {
		switch st.State {
		case health.StateUp:
			out[st.Name] = wireHealthy
		case health.StateDown:
			out[st.Name] = wireUnhealthy
		default:
			out[st.Name] = wireUnknown
		}
	}
	return out, nil
}

// replicaHealth is what a replica's own health surface renders: the verdict of
// the primary that owns the service, matched to local service IDs by name. A
// replica probes from the other side of the network, and an unreachable
// primary answers unknown for every service rather than the last value seen.
func replicaHealth(st *store.Store, p *replica.Puller) []health.Status {
	states := p.Health()
	svcs, err := st.Services()
	if err != nil {
		return nil
	}
	out := make([]health.Status, 0, len(svcs))
	for _, s := range svcs {
		out = append(out, health.Status{ServiceID: s.ID, Name: s.Name, State: localHealthState(states[s.Name])})
	}
	return out
}

// localHealthState translates the wire vocabulary back. A service this replica
// has heard no verdict for is unknown, never assumed well.
func localHealthState(wire string) string {
	switch wire {
	case wireHealthy:
		return health.StateUp
	case wireUnhealthy:
		return health.StateDown
	default:
		return health.StateUnknown
	}
}

func (s *storeSource) Version() (replica.VersionReply, error) {
	v, err := s.st.ConfigVersion()
	if err != nil {
		return replica.VersionReply{}, err
	}
	return replica.VersionReply{SchemaVersion: replica.SchemaVersion, ConfigVersion: v, NodeID: s.nodeID}, nil
}

// Snapshot reads the version before the configuration. A write landing between
// the two ships as data newer than the version it carries, which the next tick
// pulls again; the other order would have a replica record a version for a
// configuration it never received and stop asking.
func (s *storeSource) Snapshot() (replica.Snapshot, error) {
	version, err := s.st.ConfigVersion()
	if err != nil {
		return replica.Snapshot{}, err
	}
	var in store.SnapshotInput
	if in.Views, err = s.st.Views(); err != nil {
		return replica.Snapshot{}, err
	}
	if in.Services, err = s.st.Services(); err != nil {
		return replica.Snapshot{}, err
	}
	if in.Records, err = s.st.Records(); err != nil {
		return replica.Snapshot{}, err
	}
	set, ok, err := s.st.Settings()
	if err != nil {
		return replica.Snapshot{}, err
	}
	if !ok {
		return replica.Snapshot{}, errors.New("settings row vanished")
	}
	in.Settings = set
	if in.Blacklist, err = s.st.BlacklistSettings(); err != nil {
		return replica.Snapshot{}, err
	}
	// Metas, not bodies: a downloaded list belongs to the node that fetched it,
	// and shipping megabytes of domains every pull would be its own bug.
	if in.Lists, err = s.st.BlacklistListMetas(); err != nil {
		return replica.Snapshot{}, err
	}
	if in.Rules, err = s.st.BlacklistRules(); err != nil {
		return replica.Snapshot{}, err
	}
	body, err := json.Marshal(in)
	if err != nil {
		return replica.Snapshot{}, err
	}
	return replica.Snapshot{
		SchemaVersion: replica.SchemaVersion,
		ConfigVersion: version,
		NodeID:        s.nodeID,
		Config:        body,
	}, nil
}

// replicaApplier writes a pulled configuration and then rebuilds everything
// serving from it. Rows nothing has read are not replication: the zone snapshot
// would keep answering with the configuration this node had before the pull.
type replicaApplier struct {
	st       *store.Store
	settings *settings.Holder
	policy   *policy.Holder
	live     *liveComponents
}

func (a *replicaApplier) Apply(cfg json.RawMessage) error {
	if err := (replica.SnapshotApplier{Store: a.st}).Apply(cfg); err != nil {
		return err
	}
	if err := a.settings.Rebuild(); err != nil {
		return err
	}
	a.live.Apply(a.settings.Current()) // rebuilds the zone snapshot too
	return a.policy.Rebuild()
}

// primaryFingerprint is the pinned key of the primary this replica follows.
// Only replica_state answers this: peers is "the replicas I serve", and a
// demoted primary still has those rows.
func primaryFingerprint(st *store.Store) (string, error) {
	nodeID, _, err := st.ReplicaState()
	if err != nil {
		return "", err
	}
	if nodeID == "" {
		return "", errors.New("this node is not paired with a primary")
	}
	return nodeID, nil
}

// replicaAdmin is the primary's half of pairing as the admin API needs it.
// Invite goes through the replication server, so the book it mints from is the
// one /replica/pair redeems against; there is no second book to drift.
type replicaAdmin struct {
	st *store.Store
	// srv is nil unless this node serves replicas, and minting a code no
	// listener could redeem is worse than refusing.
	srv *replica.Server
}

func (a *replicaAdmin) Invite() (string, time.Time, error) {
	if a.srv == nil {
		return "", time.Time{}, adminapi.ErrNotServingReplicas
	}
	inv, err := a.srv.Mint()
	return inv.Code, inv.ExpiresAt, err
}

func (a *replicaAdmin) Peers() ([]store.Peer, error)  { return a.st.Peers() }
func (a *replicaAdmin) Unpair(nodeID string) error    { return a.st.DeletePeer(nodeID) }
func (a *replicaAdmin) ConfigVersion() (int64, error) { return a.st.ConfigVersion() }

// replicaPromoter is the operator's escape from being a replica. Every step is
// ordered so that a crash in the middle leaves a node that comes back a
// primary, never one that quietly resumes following the primary it was
// promoted away from.
type replicaPromoter struct {
	st   *store.Store
	role *RoleHolder
	// stopPull stops the pull loop and waits for it to exit. Nil on a node that
	// never had one.
	stopPull func()
}

// Promote is not atomic across its guard, so two concurrent calls can both get
// past it. Every step below is idempotent — the same record written twice, the
// same loop stopped twice, the same role set twice — so the second call costs a
// redundant write and changes nothing.
func (p *replicaPromoter) Promote() (bool, error) {
	if p.role.Current() != RoleReplica {
		return false, nil // already what the operator asked for
	}
	// Recorded first: a crash from here on must still come back a primary.
	if err := p.st.RecordPromotion(time.Now().Unix()); err != nil {
		return false, err
	}
	// Before the role flips, so no pull can land between the two and overwrite
	// the writes this node is about to start accepting.
	if p.stopPull != nil {
		p.stopPull()
	}
	if err := p.st.SetReplicaState("", 0); err != nil {
		return false, err
	}
	p.role.Set(RolePrimary)
	return true, nil
}

// replicaJoiner is this node's half of pairing. The fingerprint it pins is the
// one the operator confirmed and nothing else: a peer naming its own key would
// be authenticating itself.
type replicaJoiner struct {
	st *store.Store
	id *replica.Identity
}

func (j *replicaJoiner) Peek(ctx context.Context, address string) (string, error) {
	return replica.PeekFingerprint(ctx, address, j.id)
}

func (j *replicaJoiner) Join(ctx context.Context, address, code, fingerprint string) (string, error) {
	return replica.PairAsReplica(ctx, address, j.id, code,
		func(_ context.Context, presented string) (bool, error) { return presented == fingerprint, nil },
		pairingState{st: j.st})
}

// pairingState is the store as the pairing exchange writes it. Joining is the
// demotion of a promoted node, so recording the new primary also drops the
// promotion, and both land in one transaction: a pairing that committed while
// the promotion survived would bring the node back as a second primary. It is
// written here and not after the pairing call, because a failure there would
// have to be reported over a pairing code that is already spent.
type pairingState struct{ st *store.Store }

func (p pairingState) ReplicaState() (string, int64, error) { return p.st.ReplicaState() }

func (p pairingState) SetReplicaState(primaryNodeID string, version int64) error {
	return p.st.FollowPrimary(primaryNodeID, version)
}

// runPuller starts the pull loop and returns the function that stops it. Stop
// waits for the loop to exit rather than only signalling it: promotion must
// not race a poll that is already applying a snapshot over the writes this
// node is about to accept.
func runPuller(ctx context.Context, p *replica.Puller) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Run(ctx)
	}()
	return func() {
		cancel()
		<-done
	}
}

// replication is what startReplication built: at most one of srv and puller,
// the identity if replication is configured at all, and stopPull, which stops
// the pull loop and waits for it to exit.
type replication struct {
	srv      *replica.Server
	puller   *replica.Puller
	id       *replica.Identity
	stopPull func()
}

// startReplication starts whichever half of replication this node's role calls
// for. A standalone node does nothing here. role, not the config file, decides
// whether to follow a primary: a promoted node still has replication.primary
// in its file and must not pull from it.
func startReplication(ctx context.Context, cfg *config.Config, role Role, st *store.Store,
	ap replica.Applier, healthFn func() []health.Status, errs chan<- error, logger *slog.Logger) (replication, error) {
	if cfg.Replication.Listen == "" && cfg.Replication.Primary == "" {
		return replication{}, nil
	}
	id, err := replica.LoadOrCreateIdentity(cfg.DataDir)
	if err != nil {
		return replication{}, err
	}
	// The node ID is what an operator confirms when pairing. It is also what
	// the status endpoint and every invite report, so it is carried out of here.
	logger.Info("replication identity", "node_id", id.NodeID)

	if role == RoleReplica {
		// Without a pinned key there is nothing to authenticate the primary with,
		// so dialling it would either fail forever or trust whoever answers.
		fp, err := primaryFingerprint(st)
		if err != nil {
			logger.Warn("replication.primary is set but this node is not paired; serving the configuration it already has",
				"primary", cfg.Replication.Primary, "reason", err,
				"fix", "pair this node with its primary")
			return replication{id: id}, nil
		}
		puller := replica.NewPuller(replica.PullerConfig{
			Dial: func(context.Context) (replica.Primary, error) {
				return replica.NewClient(cfg.Replication.Primary, id, fp)
			},
			Pinned:   fp,
			Apply:    ap,
			State:    st,
			Interval: pullInterval,
			Ceiling:  pullCeiling,
			Now:      time.Now,
			Logger:   logger,
		})
		logger.Info("following primary", "primary", cfg.Replication.Primary, "primary_node_id", fp)
		return replication{puller: puller, id: id, stopPull: runPuller(ctx, puller)}, nil
	}

	// A promoted node whose file still names a primary has no listener to
	// start. It accepts writes, but no replica can follow it until the operator
	// gives it an address, so this says that rather than starting silently:
	// repointing replicas at a node with no listener fails with nothing to read.
	if cfg.Replication.Listen == "" {
		logger.Warn("this node is a primary but serves no replicas: replication.listen is not set",
			"node_id", id.NodeID,
			"fix", "set replication.listen and restart before pointing replicas at this node")
		return replication{id: id}, nil
	}

	l, err := net.Listen("tcp", cfg.Replication.Listen)
	if err != nil {
		return replication{}, fmt.Errorf("replication.listen %s: %w", cfg.Replication.Listen, err)
	}
	srv := replica.NewServer(id, st, &storeSource{st: st, nodeID: id.NodeID, health: healthFn},
		replica.NewInviteBook(inviteTTL, time.Now))
	go func() {
		// ponytail: errs is the process's fatal channel, so a replication
		// listener that dies at runtime takes DNS down with it. A later task
		// should downgrade the post-startup case to a logged error and a banner;
		// replication failing must never make local DNS unavailable.
		if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()
	peers, err := st.Peers()
	if err != nil {
		// The caller registers its Close only on success, so this one closes here
		// rather than leaking the listener and its goroutine.
		srv.Close()
		return replication{}, err
	}
	logger.Info("serving replicas", "listen", cfg.Replication.Listen, "node_id", id.NodeID, "paired", len(peers))
	return replication{srv: srv, id: id}, nil
}
