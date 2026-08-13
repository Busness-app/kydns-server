package app

import (
	"sync"

	"github.com/yoshiofthewire/kydns-server/internal/adminapi"
	"github.com/yoshiofthewire/kydns-server/internal/config"
	"github.com/yoshiofthewire/kydns-server/internal/replica"
	"github.com/yoshiofthewire/kydns-server/internal/web"
)

// Role is what this node is.
type Role string

const (
	RolePrimary    Role = "primary"
	RoleReplica    Role = "replica"
	RoleStandalone Role = "standalone"
)

// RoleFrom picks the role a fresh process boots with. Both keys set is
// already a startup error in config.validate, so this never sees that case
// and must not invent a fourth answer for it.
func RoleFrom(cfg config.ReplicationConfig) Role {
	switch {
	case cfg.Listen != "":
		return RolePrimary
	case cfg.Primary != "":
		return RoleReplica
	default:
		return RoleStandalone
	}
}

// RoleHolder is the role behind an accessor, not a constant: promotion
// (Task 7) must flip a replica to primary the instant it happens, so the
// write gates that read Current on every request stop refusing writes
// without a restart during the outage promotion exists for.
type RoleHolder struct {
	mu   sync.RWMutex
	role Role
}

// NewRoleHolder seeds the holder with the role decided at startup.
func NewRoleHolder(initial Role) *RoleHolder {
	return &RoleHolder{role: initial}
}

// Current is what write gates and the status endpoint read per request.
func (h *RoleHolder) Current() Role {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.role
}

// Set changes the live role. Task 7's Promote will call this once a replica
// wins an election; nothing else should.
func (h *RoleHolder) Set(r Role) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.role = r
}

// ReplicaStatus is what the API and UI render.
type ReplicaStatus struct {
	Role          Role   `json:"role"`
	PrimaryAddr   string `json:"primary_address,omitempty"`
	PrimaryNodeID string `json:"primary_node_id,omitempty"`
	NodeID        string `json:"node_id,omitempty"`
	LastSyncUnix  int64  `json:"last_sync_unix,omitempty"`
	LastVersion   int64  `json:"last_version,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	Stale         bool   `json:"stale,omitempty"`
}

// puller is the piece of *replica.Puller the status endpoint needs, so a
// test can supply canned status without running a pull loop.
type puller interface {
	Status() replica.Status
}

// replicaStatus renders the current role. p is nil unless this node is a
// replica, and a nil p (or the literal nil interface value) means no
// primary fields are populated. nodeID is this node's own fingerprint, empty
// on a node with no replication configured: it is what an operator confirms
// when pairing, so every invite and every status reads it from here.
func replicaStatus(role Role, primaryAddr, nodeID string, p puller) ReplicaStatus {
	rs := ReplicaStatus{Role: role, NodeID: nodeID}
	// Only a replica follows a primary, and the config still names the old one
	// after a promotion. Set before the puller check, because an unpaired
	// replica has no puller and still has to name the box to go to.
	if role == RoleReplica {
		rs.PrimaryAddr = primaryAddr
	}
	if p == nil {
		return rs
	}
	st := p.Status()
	rs.PrimaryNodeID = st.PrimaryNodeID
	if !st.LastSyncAt.IsZero() {
		rs.LastSyncUnix = st.LastSyncAt.Unix()
	}
	rs.LastVersion = st.LastVersion
	rs.LastError = st.LastError
	rs.Stale = st.Stale
	return rs
}

// toWeb converts to web's own copy of this shape, for the same reason as
// toAdminAPI: web cannot import this package.
func (s ReplicaStatus) toWeb() web.ReplicaStatus {
	return web.ReplicaStatus{
		Role: string(s.Role), PrimaryAddr: s.PrimaryAddr, LastSyncUnix: s.LastSyncUnix,
	}
}

// toAdminAPI converts to adminapi's own copy of this shape: adminapi cannot
// import this package, because this package already imports adminapi.
func (s ReplicaStatus) toAdminAPI() adminapi.ReplicaStatus {
	return adminapi.ReplicaStatus{
		Role: string(s.Role), PrimaryAddr: s.PrimaryAddr, PrimaryNodeID: s.PrimaryNodeID,
		NodeID: s.NodeID, LastSyncUnix: s.LastSyncUnix, LastVersion: s.LastVersion,
		LastError: s.LastError, Stale: s.Stale,
	}
}
