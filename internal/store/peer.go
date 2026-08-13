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

func (s *Store) PutPeer(p Peer) error {
	_, err := s.db.Exec(`
		INSERT INTO peers(node_id, label, address, paired_at, last_sync_at, last_version)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(node_id) DO UPDATE SET label = excluded.label,
		                                   address = excluded.address,
		                                   paired_at = excluded.paired_at,
		                                   last_sync_at = excluded.last_sync_at,
		                                   last_version = excluded.last_version`,
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

// TouchPeer records the outcome of a successful pull.
func (s *Store) TouchPeer(nodeID string, syncedAt, version int64) error {
	res, err := s.db.Exec(`
		UPDATE peers SET last_sync_at = ?, last_version = ? WHERE node_id = ?`,
		syncedAt, version, nodeID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: peer %s", ErrNotFound, nodeID)
	}
	return nil
}
