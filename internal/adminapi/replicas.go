package adminapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/replica"
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

// ReplicaJoiner is the replica's half of pairing, split in two because the CLI
// is not the process holding the connection whose key is being confirmed: it
// may not even run on this machine. Peek dials and reports what answered; Join
// sends the code, and only to the key the operator confirmed. Peek has nowhere
// to put a code, which is the ordering made structural.
type ReplicaJoiner interface {
	Peek(ctx context.Context, address string) (fingerprint string, err error)
	Join(ctx context.Context, address, code, fingerprint string) (primaryNodeID string, err error)
}

// WithReplicaJoiner attaches the pairing surface. It is optional: a node with
// no replication identity has nothing to pair with.
func (a *API) WithReplicaJoiner(j ReplicaJoiner) *API {
	a.replicaJoiner = j
	return a
}

// ReplicaPromoter is this node's escape from being a replica: it stops
// pulling, flips the live role, and records the promotion. app injects it, for
// the same reason as the two above.
type ReplicaPromoter interface {
	// Promote reports whether anything changed. A node that is already a
	// primary is not an error: the operator asked for a state it is in.
	Promote() (promoted bool, err error)
}

// WithReplicaPromoter attaches promotion. It is optional, so the API still
// constructs where replication is not wired.
func (a *API) WithReplicaPromoter(p ReplicaPromoter) *API {
	a.replicaPromoter = p
	return a
}

// promoteThisNode makes this node the primary. It is exempt from the write
// gate: a replica that cannot be promoted is useless in exactly the outage
// promotion exists for.
func (a *API) promoteThisNode(w http.ResponseWriter, _ *http.Request) {
	if a.replicaPromoter == nil {
		writeErr(w, http.StatusConflict, "replication_disabled", "",
			"replication is not configured on this node, so there is no role to change")
		return
	}
	promoted, err := a.replicaPromoter.Promote()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "promote_failed", "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"role": "primary", "promoted": promoted})
}

type joinRequest struct {
	Address     string `json:"address"`
	Code        string `json:"code"`
	Fingerprint string `json:"fingerprint"`
}

// peekPrimary reports the key the peer at address presents. It sends nothing:
// the operator has confirmed nothing yet, so a peer they go on to decline must
// learn nothing from having been dialled.
func (a *API) peekPrimary(w http.ResponseWriter, r *http.Request) {
	var req joinRequest
	if !a.joinRequest(w, r, &req) {
		return
	}
	fp, err := a.replicaJoiner.Peek(r.Context(), req.Address)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "peek_failed", "address", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"fingerprint": fp})
}

// joinPrimary pairs with address, pinned to the fingerprint the operator
// confirmed. The fingerprint is required: there is no prompt-free default that
// trusts whatever answered, here or in the CLI above it.
func (a *API) joinPrimary(w http.ResponseWriter, r *http.Request) {
	var req joinRequest
	if !a.joinRequest(w, r, &req) {
		return
	}
	fingerprint := strings.TrimSpace(req.Fingerprint)
	if fingerprint == "" {
		writeErr(w, http.StatusBadRequest, "fingerprint_required", "fingerprint",
			"pairing needs the fingerprint the operator confirmed; peek first")
		return
	}
	nodeID, err := a.replicaJoiner.Join(r.Context(), req.Address, req.Code, fingerprint)
	if err != nil {
		// Its own code: a rejected fingerprint may mean something is in the path,
		// which reads nothing like a peer that failed to answer.
		if errors.Is(err, replica.ErrFingerprintRejected) {
			writeErr(w, http.StatusConflict, "fingerprint_mismatch", "fingerprint", err.Error())
			return
		}
		writeErr(w, http.StatusBadGateway, "pair_failed", "address", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"primary_node_id": nodeID})
}

// joinRequest decodes the body both pairing calls share and refuses the two
// cases neither can do anything with.
func (a *API) joinRequest(w http.ResponseWriter, r *http.Request, req *joinRequest) bool {
	if a.replicaJoiner == nil {
		writeErr(w, http.StatusConflict, "replication_disabled", "",
			"replication is not configured on this node; set replication.primary and restart before pairing")
		return false
	}
	if !decode(w, r, req) {
		return false
	}
	if strings.TrimSpace(req.Address) == "" {
		writeErr(w, http.StatusBadRequest, "address_required", "address", "an address to pair with is required")
		return false
	}
	return true
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
