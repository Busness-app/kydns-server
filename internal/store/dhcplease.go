package store

// DHCP leases are node-local: they are not replicated and no cv_ trigger
// names this table. They are persisted only so a restart cannot re-issue an
// address that is still in use.

// DHCPLeases returns every stored lease, expired ones included. Pruning is
// the allocator's job, on the schedule that suits it.
func (s *Store) DHCPLeases() ([]DHCPLease, error) {
	rows, err := s.db.Query(
		`SELECT mac, ip, hostname, expires_at, last_seen FROM dhcp_leases ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DHCPLease
	for rows.Next() {
		var l DHCPLease
		if err := rows.Scan(&l.MAC, &l.IP, &l.Hostname, &l.ExpiresAt, &l.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// PutDHCPLease stores one lease. Both keys move: a client can be given a new
// address, and a released address can be re-issued to a different client. The
// two deletes clear whichever unique key the new row would collide with, so
// this is an upsert on either.
func (s *Store) PutDHCPLease(l DHCPLease) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM dhcp_leases WHERE ip = ? AND mac <> ?`, l.IP, l.MAC); err != nil {
		return err
	}
	if _, err := tx.Exec(`
INSERT INTO dhcp_leases (mac, ip, hostname, expires_at, last_seen)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(mac) DO UPDATE SET
  ip=excluded.ip, hostname=excluded.hostname,
  expires_at=excluded.expires_at, last_seen=excluded.last_seen`,
		l.MAC, l.IP, l.Hostname, l.ExpiresAt, l.LastSeen); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteDHCPLease drops one lease. Deleting one that is not there is not an
// error: a client may send RELEASE more than once.
func (s *Store) DeleteDHCPLease(mac string) error {
	_, err := s.db.Exec(`DELETE FROM dhcp_leases WHERE mac = ?`, mac)
	return err
}

// DeleteExpiredDHCPLeases prunes leases that expired at or before now, and
// returns how many went.
func (s *Store) DeleteExpiredDHCPLeases(now int64) (int, error) {
	res, err := s.db.Exec(`DELETE FROM dhcp_leases WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
