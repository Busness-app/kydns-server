package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// Peer is a linked node this one trusts, keyed by its fingerprint. The peers
// table is node-local and carries no config_version trigger.
type Peer struct {
	NodeID      string
	Label       string
	Address     string
	PairedAt    int64
	LastSyncAt  int64
	LastVersion int64
}

// PairPeer records a pairing. A re-pair refreshes only what the pairing itself
// establishes: the label an operator gave the node and its sync history belong
// to the peer, not to the handshake, and pairing sends a generated label every
// time. A name that vanishes when a node re-pairs makes the whole replica list
// untrustworthy.
func (s *Store) PairPeer(p Peer) error {
	_, err := s.db.Exec(`
		INSERT INTO peers(node_id, label, address, paired_at, last_sync_at, last_version)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(node_id) DO UPDATE SET address = excluded.address,
		                                   paired_at = excluded.paired_at`,
		p.NodeID, p.Label, p.Address, p.PairedAt, p.LastSyncAt, p.LastVersion)
	return err
}

func (s *Store) Peers() ([]Peer, error) {
	rows, err := s.db.Query(`
		SELECT node_id, label, address, paired_at, last_sync_at, last_version
		FROM peers ORDER BY label, node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Peer{}
	for rows.Next() {
		var p Peer
		if err := rows.Scan(&p.NodeID, &p.Label, &p.Address, &p.PairedAt, &p.LastSyncAt, &p.LastVersion); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) Peer(nodeID string) (Peer, error) {
	var p Peer
	err := s.db.QueryRow(`
		SELECT node_id, label, address, paired_at, last_sync_at, last_version
		FROM peers WHERE node_id = ?`, nodeID).
		Scan(&p.NodeID, &p.Label, &p.Address, &p.PairedAt, &p.LastSyncAt, &p.LastVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return Peer{}, fmt.Errorf("%w: peer %s", ErrNotFound, nodeID)
	}
	return p, err
}

func (s *Store) DeletePeer(nodeID string) error {
	res, err := s.db.Exec(`DELETE FROM peers WHERE node_id = ?`, nodeID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: peer %s", ErrNotFound, nodeID)
	}
	return nil
}

// ReplicaState is the primary's version this node last applied. It is kept
// apart from peers because re-pairing rewrites that row, and apart from
// config_version because applying a snapshot bumps this node's own counter.
func (s *Store) ReplicaState() (string, int64, error) {
	var nodeID string
	var version int64
	err := s.db.QueryRow(`SELECT primary_node_id, last_version FROM replica_state WHERE id = 1`).
		Scan(&nodeID, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	return nodeID, version, err
}

func (s *Store) SetReplicaState(primaryNodeID string, version int64) error {
	_, err := s.db.Exec(`
		INSERT INTO replica_state(id, primary_node_id, last_version) VALUES(1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET primary_node_id = excluded.primary_node_id,
		                              last_version = excluded.last_version`,
		primaryNodeID, version)
	return err
}

// Promotion is when this node was promoted to primary, or 0 if it never was.
// It is the answer that beats replication.primary in the config file, because
// promotion records itself here rather than editing that file.
func (s *Store) Promotion() (int64, error) {
	var at int64
	err := s.db.QueryRow(`SELECT promoted_at FROM promotion WHERE id = 1`).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return at, err
}

func (s *Store) RecordPromotion(at int64) error {
	_, err := s.db.Exec(`
		INSERT INTO promotion(id, promoted_at) VALUES(1, ?)
		ON CONFLICT(id) DO UPDATE SET promoted_at = excluded.promoted_at`, at)
	return err
}

// ClearPromotion undoes a promotion. Joining a primary is the demotion, and a
// node that kept the record would come back a primary on its next restart.
func (s *Store) ClearPromotion() error {
	_, err := s.db.Exec(`DELETE FROM promotion WHERE id = 1`)
	return err
}

// TouchPeer records the outcome of a successful pull. version is the version
// the peer reported holding; nil leaves the recorded one alone, so a peer that
// reports nothing still updates its last-seen time.
func (s *Store) TouchPeer(nodeID string, syncedAt int64, version *int64) error {
	res, err := s.db.Exec(`
		UPDATE peers SET last_sync_at = ?, last_version = COALESCE(?, last_version)
		WHERE node_id = ?`,
		syncedAt, version, nodeID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: peer %s", ErrNotFound, nodeID)
	}
	return nil
}
