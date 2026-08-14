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

// ErrReplicationDisabled is what the exported calls return where nothing is
// wired: no peers to manage, no role to change.
var ErrReplicationDisabled = errors.New("replication is not configured on this node")

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

// PromoteThisNode makes this node the primary and reports the role it holds
// afterwards. Exported because the web screen's promote button runs the same
// rules: a second implementation of them is a second thing to get wrong.
func (a *API) PromoteThisNode() (role string, promoted bool, err error) {
	if a.replicaPromoter == nil {
		return "", false, ErrReplicationDisabled
	}
	if promoted, err = a.replicaPromoter.Promote(); err != nil {
		return "", false, err
	}
	// The role is read back rather than assumed: a standalone node has no
	// primary to stop following, and telling it that it is one sends the
	// operator looking for replicas that were never there.
	role = "primary"
	if a.replicaStatus != nil {
		role = a.replicaStatus().Role
	}
	return role, promoted, nil
}

// promoteThisNode is exempt from the write gate: a replica that cannot be
// promoted is useless in exactly the outage promotion exists for.
func (a *API) promoteThisNode(w http.ResponseWriter, _ *http.Request) {
	role, promoted, err := a.PromoteThisNode()
	switch {
	case errors.Is(err, ErrReplicationDisabled):
		writeErr(w, http.StatusConflict, "replication_disabled", "",
			"replication is not configured on this node, so there is no role to change")
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "promote_failed", "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"role": role, "promoted": promoted})
}

type joinRequest struct {
	Address     string `json:"address"`
	Code        string `json:"code"`
	Fingerprint string `json:"fingerprint"`
}

// peekRequest is an address and nothing else. Sharing joinRequest would decode
// a code POSTed here into this daemon's memory before discarding it; a struct
// with nowhere to put one cannot.
type peekRequest struct {
	Address string `json:"address"`
}

// peekPrimary reports the key the peer at address presents. It sends nothing:
// the operator has confirmed nothing yet, so a peer they go on to decline must
// learn nothing from having been dialled.
func (a *API) peekPrimary(w http.ResponseWriter, r *http.Request) {
	var req peekRequest
	if !a.pairingRequest(w, r, &req, &req.Address) {
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
	if !a.pairingRequest(w, r, &req, &req.Address) {
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

// pairingRequest decodes into whichever body the call takes and refuses the two
// cases neither can do anything with. address points into req, because the
// address is the only field the two share.
func (a *API) pairingRequest(w http.ResponseWriter, r *http.Request, req any, address *string) bool {
	if a.replicaJoiner == nil {
		writeErr(w, http.StatusConflict, "replication_disabled", "",
			"replication is not configured on this node; set replication.primary and restart before pairing")
		return false
	}
	if !decode(w, r, req) {
		return false
	}
	if strings.TrimSpace(*address) == "" {
		writeErr(w, http.StatusBadRequest, "address_required", "address", "an address to pair with is required")
		return false
	}
	return true
}

// The three peer states an operator acts on. A peer that has never answered is
// not "0 behind": it is a pairing that never became a replica.
const (
	StatusNeverSynced = "never_synced"
	StatusBehind      = "behind"
	StatusInSync      = "in_sync"
)

// ReplicaRow is one peer as both transports render it.
type ReplicaRow struct {
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
	code, expires, nodeID, err := a.InviteReplica()
	switch {
	case errors.Is(err, ErrNotServingReplicas):
		writeErr(w, http.StatusConflict, "replication_disabled", "",
			"replication is not enabled on this node; set replication.listen to serve replicas")
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "invite_failed", "", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"code":       code,
		"expires_at": expires.Unix(),
		"node_id":    nodeID,
	})
}

// InviteReplica mints a pairing code and returns it with this node's
// fingerprint. Exported so the web screen shows the pair the CLI prints,
// from one call: neither transport can display a code without the key beside
// it, because there is no call here that returns only one of them.
func (a *API) InviteReplica() (code string, expiresAt time.Time, nodeID string, err error) {
	if a.replicaAdmin == nil {
		return "", time.Time{}, "", ErrNotServingReplicas
	}
	// Checked before minting: a code printed beside a blank fingerprint is an
	// invitation to trust whoever answers, which is the one thing this design
	// exists to prevent. A node with no key to show has nothing to pair with.
	if nodeID = a.thisNodeID(); nodeID == "" {
		return "", time.Time{}, "", ErrNotServingReplicas
	}
	code, expiresAt, err = a.replicaAdmin.Invite()
	if err != nil {
		return "", time.Time{}, "", err
	}
	return code, expiresAt, nodeID, nil
}

// ReplicaRows reports the peers this node serves and the config version their
// lag is measured against. Exported for the web screen, so the lag and status
// rules live in one place.
func (a *API) ReplicaRows() ([]ReplicaRow, int64, error) {
	rows := []ReplicaRow{}
	if a.replicaAdmin == nil {
		return rows, 0, nil
	}
	version, err := a.replicaAdmin.ConfigVersion()
	if err != nil {
		return nil, 0, err
	}
	peers, err := a.replicaAdmin.Peers()
	if err != nil {
		return nil, 0, err
	}
	for _, p := range peers {
		rows = append(rows, toReplicaRow(p, version))
	}
	return rows, version, nil
}

// RemoveReplica unpairs a peer. Exported for the web screen's remove control.
func (a *API) RemoveReplica(nodeID string) error {
	if a.replicaAdmin == nil {
		return ErrReplicationDisabled
	}
	return a.replicaAdmin.Unpair(nodeID)
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
	rows, version, err := a.ReplicaRows()
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"replicas": rows, "config_version": version})
}

func toReplicaRow(p store.Peer, version int64) ReplicaRow {
	r := ReplicaRow{
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
		r.Status = StatusNeverSynced
	case r.Lag > 0:
		r.Status = StatusBehind
	default:
		r.Status = StatusInSync
	}
	return r
}

func (a *API) removeReplica(w http.ResponseWriter, r *http.Request) {
	err := a.RemoveReplica(r.PathValue("node_id"))
	if errors.Is(err, ErrReplicationDisabled) {
		writeErr(w, http.StatusNotFound, "not_found", "node_id", "this node serves no replicas")
		return
	}
	if err != nil {
		writeRegistryErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
