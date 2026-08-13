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

	"github.com/yoshiofthewire/kydns-server/internal/config"
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
// replica_state names it once a pull has landed; before that, pairing has
// written exactly one peer.
func primaryFingerprint(st *store.Store) (string, error) {
	nodeID, _, err := st.ReplicaState()
	if err != nil {
		return "", err
	}
	if nodeID != "" {
		return nodeID, nil
	}
	peers, err := st.Peers()
	if err != nil {
		return "", err
	}
	if len(peers) != 1 {
		return "", fmt.Errorf("%d peers are pinned, a replica follows exactly one", len(peers))
	}
	return peers[0].NodeID, nil
}

// startReplication starts whichever half of replication the config file asked
// for. A standalone node does nothing here. The returned server is nil unless
// this node is a primary.
func startReplication(ctx context.Context, cfg *config.Config, st *store.Store,
	ap replica.Applier, errs chan<- error, logger *slog.Logger) (*replica.Server, error) {
	if cfg.Replication.Listen == "" && cfg.Replication.Primary == "" {
		return nil, nil
	}
	id, err := replica.LoadOrCreateIdentity(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	// The node ID is what an operator confirms when pairing, and there is no CLI
	// yet to print it.
	logger.Info("replication identity", "node_id", id.NodeID)

	if cfg.Replication.Primary != "" {
		// Without a pinned key there is nothing to authenticate the primary with,
		// so dialling it would either fail forever or trust whoever answers.
		fp, err := primaryFingerprint(st)
		if err != nil {
			logger.Warn("replication.primary is set but this node is not paired; serving the configuration it already has",
				"primary", cfg.Replication.Primary, "reason", err,
				"fix", "pair this node with its primary")
			return nil, nil
		}
		dial := func(ctx context.Context) (replica.Primary, error) {
			return replica.Dial(ctx, cfg.Replication.Primary, id, fp)
		}
		go replica.NewPuller(dial, ap, st, pullInterval, pullCeiling, time.Now).Run(ctx)
		logger.Info("following primary", "primary", cfg.Replication.Primary, "primary_node_id", fp)
		return nil, nil
	}

	l, err := net.Listen("tcp", cfg.Replication.Listen)
	if err != nil {
		return nil, fmt.Errorf("replication.listen %s: %w", cfg.Replication.Listen, err)
	}
	srv := replica.NewServer(id, st, &storeSource{st: st, nodeID: id.NodeID},
		replica.NewInviteBook(inviteTTL, time.Now))
	go func() {
		if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()
	peers, err := st.Peers()
	if err != nil {
		return srv, err
	}
	logger.Info("serving replicas", "listen", cfg.Replication.Listen, "node_id", id.NodeID, "paired", len(peers))
	return srv, nil
}
