package adminapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// ErrNotServingReplicas is what Invite returns on a node with no replication
// listener. There is no book to mint from, and a code nothing can redeem is
// worse than a refusal: the operator would type it into the other box and be
// told only that pairing failed.
var ErrNotServingReplicas = errors.New("this node is not serving replicas")

// ReplicaAdmin is the primary's half of pairing. app injects it, because
// adminapi cannot import app: app already imports adminapi. Invite mints from
// the replication listener's own book, so a code handed to an operator here is
// one the pairing endpoint there will redeem.
type ReplicaAdmin interface {
	Invite() (code string, expiresAt time.Time, err error)
	Peers() ([]store.Peer, error)
	Unpair(nodeID string) error
	// ConfigVersion is this node's current version, the one a peer's recorded
	// version lags behind.
	ConfigVersion() (int64, error)
}

// WithReplicaAdmin attaches the replica management surface. It is optional, so
// the API still constructs where replication is not wired.
func (a *API) WithReplicaAdmin(r ReplicaAdmin) *API {
	a.replicaAdmin = r
	return a
}

// The three peer states an operator acts on. A peer that has never answered is
// not "0 behind": it is a pairing that never became a replica.
const (
	statusNeverSynced = "never_synced"
	statusBehind      = "behind"
	statusInSync      = "in_sync"
)

type replicaRow struct {
	NodeID      string `json:"node_id"`
	Label       string `json:"label,omitempty"`
	Address     string `json:"address,omitempty"`
	PairedAt    int64  `json:"paired_at,omitempty"`
	LastSyncAt  int64  `json:"last_sync_at"`
	LastVersion int64  `json:"last_version"`
	Lag         int64  `json:"lag"`
	Status      string `json:"status"`
}

// inviteReplica mints a pairing code and returns it with this node's
// fingerprint. Both, together, because pairing is the SSH model: the operator
// confirms the key on the replica before the code is sent, and a code with no
// fingerprint beside it invites them to skip that and trust whoever answers.
//
// The code is written to this response and nowhere else. It is never logged.
func (a *API) inviteReplica(w http.ResponseWriter, _ *http.Request) {
	if a.replicaAdmin == nil {
		writeErr(w, http.StatusConflict, "replication_disabled", "",
			"replication is not enabled on this node; set replication.listen to serve replicas")
		return
	}
	code, expires, err := a.replicaAdmin.Invite()
	if err != nil {
		if errors.Is(err, ErrNotServingReplicas) {
			writeErr(w, http.StatusConflict, "replication_disabled", "",
				"replication is not enabled on this node; set replication.listen to serve replicas")
			return
		}
		writeErr(w, http.StatusInternalServerError, "invite_failed", "", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"code":       code,
		"expires_at": expires.Unix(),
		"node_id":    a.thisNodeID(),
	})
}

// thisNodeID is the fingerprint an operator confirms at pairing. It comes from
// the same status producer the dashboard reads, so the two can never name
// different keys for one node.
func (a *API) thisNodeID() string {
	if a.replicaStatus == nil {
		return ""
	}
	return a.replicaStatus().NodeID
}

// listReplicas reports the peers this node serves. It is a read, so it answers
// on a replica too: peers is "the replicas I serve", which a replica normally
// has none of, and a demoted primary still holds rows an operator needs to see
// to clean up.
func (a *API) listReplicas(w http.ResponseWriter, _ *http.Request) {
	rows := []replicaRow{}
	var version int64
	if a.replicaAdmin != nil {
		var err error
		if version, err = a.replicaAdmin.ConfigVersion(); err != nil {
			writeRegistryErr(w, err)
			return
		}
		peers, err := a.replicaAdmin.Peers()
		if err != nil {
			writeRegistryErr(w, err)
			return
		}
		for _, p := range peers {
			rows = append(rows, toReplicaRow(p, version))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"replicas": rows, "config_version": version})
}

func toReplicaRow(p store.Peer, version int64) replicaRow {
	r := replicaRow{
		NodeID: p.NodeID, Label: p.Label, Address: p.Address, PairedAt: p.PairedAt,
		LastSyncAt: p.LastSyncAt, LastVersion: p.LastVersion,
		Lag: version - p.LastVersion,
	}
	// A peer ahead of this node is not something to render as negative lag: it
	// happens for a moment around a write, and again after a promotion.
	if r.Lag < 0 {
		r.Lag = 0
	}
	switch {
	case p.LastSyncAt == 0:
		r.Status = statusNeverSynced
	case r.Lag > 0:
		r.Status = statusBehind
	default:
		r.Status = statusInSync
	}
	return r
}

func (a *API) removeReplica(w http.ResponseWriter, r *http.Request) {
	if a.replicaAdmin == nil {
		writeErr(w, http.StatusNotFound, "not_found", "node_id", "this node serves no replicas")
		return
	}
	if err := a.replicaAdmin.Unpair(r.PathValue("node_id")); err != nil {
		writeRegistryErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
