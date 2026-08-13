package store

// ConfigVersion is the counter replicas poll. It is maintained by triggers on
// the replicated tables, so it moves for exactly the writes a replica needs to
// hear about and for no others.
func (s *Store) ConfigVersion() (int64, error) {
	var v int64
	err := s.db.QueryRow(`SELECT version FROM config_version WHERE id = 1`).Scan(&v)
	return v, err
}
