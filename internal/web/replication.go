package web

import (
	"errors"
	"maps"
	"net/http"
	"strconv"
	"time"

	"github.com/Busness-app/kydns-server/internal/adminapi"
	"github.com/Busness-app/kydns-server/internal/replica"
)

// roleStandalone mirrors app.Role's standalone value, for the same reason
// roleReplica does: web cannot import internal/app.
const roleStandalone = "standalone"

// role is what this node is. No replication wiring is a standalone node,
// which has no peers, no primary, and nothing to promote.
func (s *Server) role() string {
	if s.o.Replication == nil {
		return roleStandalone
	}
	if r := s.o.Replication().Role; r != "" {
		return r
	}
	return roleStandalone
}

// replicating reports whether this node has a replication screen at all.
func (s *Server) replicating() bool { return s.role() != roleStandalone }

// peerRow is one replica as the screen shows it: ages and states in words,
// because the raw enum and a unix stamp are not what an operator reads.
type peerRow struct {
	NodeID   string
	Label    string
	Address  string
	LastSync string
	Status   string
	Lag      int64
	Synced   bool
}

// peerStatusText renders adminapi's states. The raw values are wire strings,
// and "never_synced" on a screen reads like a column name.
var peerStatusText = map[string]string{
	adminapi.StatusInSync:      "in sync",
	adminapi.StatusBehind:      "behind",
	adminapi.StatusNeverSynced: "never synced",
}

// peerRows asks adminapi for the peers, so lag and status are computed once
// for both transports.
func (s *Server) peerRows(now time.Time) ([]peerRow, error) {
	if s.o.API == nil {
		return nil, nil
	}
	rows, _, err := s.o.API.ReplicaRows()
	if err != nil {
		return nil, err
	}
	out := make([]peerRow, 0, len(rows))
	for _, r := range rows {
		p := peerRow{
			NodeID: r.NodeID, Label: r.Label, Address: r.Address,
			LastSync: sinceText(r.LastSyncAt, now), Lag: r.Lag,
			Status: r.Status, Synced: r.LastSyncAt != 0,
		}
		if text, ok := peerStatusText[r.Status]; ok {
			p.Status = text
		}
		out = append(out, p)
	}
	return out, nil
}

// inviteView is a minted code beside the fingerprint the operator compares on
// the far machine. One struct, so neither can be rendered without the other.
type inviteView struct {
	Code        string
	Fingerprint string
	ExpiresIn   string
}

func (s *Server) getReplication(w http.ResponseWriter, r *http.Request) {
	s.renderReplication(w, r, http.StatusOK, nil)
}

// renderReplication draws the screen with whatever a POST has to add. A
// standalone node has no screen: it goes to the dashboard rather than to a
// page with nothing on it, which is why status is passed in rather than
// written by the caller: a refusal that turns into a redirect would otherwise
// be a status with no body behind it.
func (s *Server) renderReplication(w http.ResponseWriter, r *http.Request, status int, extra map[string]any) {
	if !s.replicating() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	data := s.replicationData()
	maps.Copy(data, extra)
	s.render(w, r, "replication.html", data)
}

func (s *Server) replicationData() map[string]any {
	role := s.role()
	data := map[string]any{"Title": "Replication", "Nav": "replication", "Role": role}
	if st, isReplica := s.replica(); isReplica {
		data["PrimaryAddr"] = st.managedBy()
		data["SyncAge"] = sinceText(st.LastSyncUnix, time.Now())
		// The screen an operator opens when replication looks wrong is this one,
		// so what the last poll reported belongs on it.
		data["LastError"] = st.LastError
		data["Paired"] = st.Paired
		// A form with no pairing surface behind it is a button that cannot work.
		data["CanPair"] = s.o.API != nil && s.o.API.CanPair()
		return data
	}
	rows, err := s.peerRows(time.Now())
	if err != nil {
		data["Error"] = err.Error()
		return data
	}
	data["Peers"] = rows
	return data
}

// postReplicaInvite mints a code and shows it with this node's fingerprint.
// The code is a credential valid for minutes: it is written to this response
// and nowhere else, which is why this renders rather than redirects.
func (s *Server) postReplicaInvite(w http.ResponseWriter, r *http.Request) {
	if s.o.API == nil {
		s.renderReplication(w, r, http.StatusConflict, replicationOff)
		return
	}
	code, expires, fingerprint, err := s.o.API.InviteReplica()
	if err != nil {
		s.renderReplication(w, r, http.StatusConflict, map[string]any{"Error": inviteErrorText(err)})
		return
	}
	// The page holds a credential good for ten minutes. Nothing is meant to
	// keep it, but a shared browser's back button and bfcache would.
	w.Header().Set("Cache-Control", "no-store")
	s.renderReplication(w, r, http.StatusOK, map[string]any{"Invite": inviteView{
		Code: code, Fingerprint: fingerprint, ExpiresIn: shortDuration(time.Until(expires)),
	}})
}

func (s *Server) postReplicaRemove(w http.ResponseWriter, r *http.Request) {
	if s.o.API == nil {
		s.renderReplication(w, r, http.StatusConflict, replicationOff)
		return
	}
	if err := s.o.API.RemoveReplica(r.PostFormValue("node_id")); err != nil {
		s.renderReplication(w, r, http.StatusBadRequest, map[string]any{"Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/replication", http.StatusSeeOther)
}

// inviteErrorText says what to change, matching the sentence the JSON path
// gives. A bare "not serving replicas" leaves the operator with no key to set.
func inviteErrorText(err error) string {
	if errors.Is(err, adminapi.ErrNotServingReplicas) {
		return err.Error() + "; set replication.listen to serve replicas and restart"
	}
	return err.Error()
}

// replicationOff is what a screen with no replication wiring behind it says.
var replicationOff = map[string]any{"Error": adminapi.ErrReplicationDisabled.Error()}

const promoteUnconfirmed = "Nothing changed: the promotion was not confirmed."

// postReplicaPromote is registered at PathPromote, the one web write the
// replica gate exempts. The confirmation is checked here and not only in the
// markup: promotion is the state this design can neither detect nor undo, so
// it must not turn on a stray click or a replayed form.
func (s *Server) postReplicaPromote(w http.ResponseWriter, r *http.Request) {
	if r.PostFormValue("confirm") == "" {
		s.renderReplication(w, r, http.StatusBadRequest, map[string]any{"Error": promoteUnconfirmed})
		return
	}
	if s.o.API == nil {
		s.renderReplication(w, r, http.StatusConflict, replicationOff)
		return
	}
	role, promoted, err := s.o.API.PromoteThisNode()
	if err != nil {
		s.renderReplication(w, r, http.StatusConflict, map[string]any{"Error": err.Error()})
		return
	}
	s.renderReplication(w, r, http.StatusOK, map[string]any{"Promoted": promoted, "RoleAfter": role})
}

const (
	joinUnconfirmed = "Nothing changed: re-pairing was not confirmed."
	joinPaired      = "Paired. This node does not start following its primary until KyDNS is restarted."
	joinCodeUnsent  = "The code was not sent, so it is still good."
	joinNotReplica  = "Only a replica pairs with a primary. Set replication.primary in this node's config and restart."
)

// postReplicaJoin pairs this node with the primary its config already names.
// Registered at PathJoin, the second write the replica gate exempts.
//
// The address is this node's configured primary and never the operator's
// input: the pull loop dials replication.primary, so pairing with anything
// else produces a node that is paired and polls someone else forever.
func (s *Server) postReplicaJoin(w http.ResponseWriter, r *http.Request) {
	if s.o.API == nil {
		s.renderReplication(w, r, http.StatusConflict, replicationOff)
		return
	}
	st, isReplica := s.replica()
	if !isReplica {
		s.renderReplication(w, r, http.StatusConflict, map[string]any{"Error": joinNotReplica})
		return
	}
	// Pairing again discards a link that works, which the operator has to mean,
	// the way promotion does. A node with nothing pinned has nothing to lose.
	if st.Paired && r.PostFormValue("confirm") == "" {
		s.renderReplication(w, r, http.StatusBadRequest, map[string]any{"Error": joinUnconfirmed})
		return
	}
	// The request carried a live code, so the page it produces is not one for a
	// shared browser to keep.
	w.Header().Set("Cache-Control", "no-store")
	_, err := s.o.API.JoinPrimary(r.Context(), st.PrimaryAddr,
		r.PostFormValue("code"), r.PostFormValue("fingerprint"))
	switch {
	case err == nil:
		s.renderReplication(w, r, http.StatusOK, map[string]any{"Joined": joinPaired})
	case errors.Is(err, adminapi.ErrFingerprintRequired):
		s.renderReplication(w, r, http.StatusBadRequest, map[string]any{"Error": err.Error()})
	case errors.Is(err, adminapi.ErrReplicationDisabled):
		s.renderReplication(w, r, http.StatusConflict, replicationOff)
	case errors.Is(err, replica.ErrFingerprintRejected):
		// Something may be answering in the primary's place. Saying the code
		// survived is the difference between retrying and minting another.
		s.renderReplication(w, r, http.StatusConflict, map[string]any{
			"Error": err.Error() + ". " + joinCodeUnsent,
		})
	default:
		s.renderReplication(w, r, http.StatusBadGateway, map[string]any{"Error": err.Error()})
	}
}

// replicationLine is the dashboard's one line about replication: what this
// node is, and the one number that says whether it is working.
type replicationLine struct {
	Role   string
	Detail string
	Label  string
}

// replicationSummary is nil on a standalone node, which has nothing to say.
func (s *Server) replicationSummary() *replicationLine {
	if !s.replicating() {
		return nil
	}
	if st, isReplica := s.replica(); isReplica {
		return &replicationLine{
			Role:   roleReplica,
			Detail: "synced " + sinceText(st.LastSyncUnix, time.Now()),
			Label:  "Following " + st.managedBy(),
		}
	}
	line := &replicationLine{Role: s.role(), Label: "Replicas"}
	rows, err := s.peerRows(time.Now())
	if err != nil {
		line.Detail = "unavailable"
		return line
	}
	line.Detail = "1 replica"
	if len(rows) != 1 {
		line.Detail = strconv.Itoa(len(rows)) + " replicas"
	}
	return line
}
