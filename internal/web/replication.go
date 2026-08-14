package web

import (
	"maps"
	"net/http"
	"strconv"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/adminapi"
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
	s.renderReplication(w, r, nil)
}

// renderReplication draws the screen with whatever a POST has to add. A
// standalone node has no screen: it goes to the dashboard rather than to a
// page with nothing on it.
func (s *Server) renderReplication(w http.ResponseWriter, r *http.Request, extra map[string]any) {
	if !s.replicating() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
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
		w.WriteHeader(http.StatusConflict)
		s.renderReplication(w, r, map[string]any{"Error": adminapi.ErrReplicationDisabled.Error()})
		return
	}
	code, expires, fingerprint, err := s.o.API.InviteReplica()
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		s.renderReplication(w, r, map[string]any{"Error": err.Error()})
		return
	}
	s.renderReplication(w, r, map[string]any{"Invite": inviteView{
		Code: code, Fingerprint: fingerprint, ExpiresIn: shortDuration(time.Until(expires)),
	}})
}

func (s *Server) postReplicaRemove(w http.ResponseWriter, r *http.Request) {
	if s.o.API == nil {
		w.WriteHeader(http.StatusConflict)
		s.renderReplication(w, r, map[string]any{"Error": adminapi.ErrReplicationDisabled.Error()})
		return
	}
	if err := s.o.API.RemoveReplica(r.PostFormValue("node_id")); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		s.renderReplication(w, r, map[string]any{"Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/replication", http.StatusSeeOther)
}

const promoteUnconfirmed = "Nothing changed: the promotion was not confirmed."

// postReplicaPromote is registered at PathPromote, the one web write the
// replica gate exempts. The confirmation is checked here and not only in the
// markup: promotion is the state this design can neither detect nor undo, so
// it must not turn on a stray click or a replayed form.
func (s *Server) postReplicaPromote(w http.ResponseWriter, r *http.Request) {
	if r.PostFormValue("confirm") == "" {
		w.WriteHeader(http.StatusBadRequest)
		s.renderReplication(w, r, map[string]any{"Error": promoteUnconfirmed})
		return
	}
	if s.o.API == nil {
		w.WriteHeader(http.StatusConflict)
		s.renderReplication(w, r, map[string]any{"Error": adminapi.ErrReplicationDisabled.Error()})
		return
	}
	role, promoted, err := s.o.API.PromoteThisNode()
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		s.renderReplication(w, r, map[string]any{"Error": err.Error()})
		return
	}
	s.renderReplication(w, r, map[string]any{"Promoted": promoted, "RoleAfter": role})
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
