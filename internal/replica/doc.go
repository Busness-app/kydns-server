// Package replica implements linked-server replication: one primary that
// serves configuration snapshots, and replicas that pull them.
package replica

import "encoding/json"

// SchemaVersion is the replication wire format. A peer on a different version
// is refused rather than coerced: a replica must never guess at a document a
// newer primary wrote.
const SchemaVersion = 1

// VersionReply answers the cheap poll. It is deliberately tiny — a replica
// asks for it every five seconds and almost always learns nothing changed.
type VersionReply struct {
	SchemaVersion int    `json:"schema_version"`
	ConfigVersion int64  `json:"config_version"`
	NodeID        string `json:"node_id"`
}

// Snapshot is the whole replicated configuration plus the version it was read
// at. The version is read first, so a write landing mid-read ships a body
// newer than its version and the replica pulls again; the other order would
// have it record a version for a configuration it never received.
type Snapshot struct {
	SchemaVersion int             `json:"schema_version"`
	ConfigVersion int64           `json:"config_version"`
	NodeID        string          `json:"node_id"`
	Config        json.RawMessage `json:"config"`
}

// HealthReply answers /replica/health-status. It is its own request rather
// than a field on VersionReply: health changes constantly and must never look
// like a configuration change to a replica watching config_version.
type HealthReply struct {
	Statuses map[string]string `json:"statuses"`
}
