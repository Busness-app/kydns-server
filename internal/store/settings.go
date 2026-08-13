package store

import (
	"database/sql"
	"errors"
	"strings"
)

// The three list columns are newline-separated text. They are always read and
// written whole and their order is positional, so a child table would buy only
// joins.
// ponytail: split into settings_list(kind, ord, value) if a per-entry edit
// (reorder one upstream, delete one prefix) ever appears in the UI.
func packList(v []string) string { return strings.Join(v, "\n") }

func unpackList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// Settings returns the stored settings. The bool is false when no row exists,
// which is how a first run knows to seed from the config file.
func (s *Store) Settings() (Settings, bool, error) {
	var v Settings
	var rz, up, aq string
	err := s.db.QueryRow(`
SELECT private_domain, reverse_zones, upstreams, allow_query, allow_tailscale,
       ttl, cache_min_ttl, cache_max_ttl, negative_max_ttl, cache_entries,
       log_queries, log_client_ip, dhcp_lease_file, discovery_interval,
       health_interval, health_timeout, health_workers
FROM settings WHERE id = 1`).Scan(
		&v.PrivateDomain, &rz, &up, &aq, &v.AllowTailscale,
		&v.TTL, &v.CacheMinTTL, &v.CacheMaxTTL, &v.NegativeMaxTTL, &v.CacheEntries,
		&v.LogQueries, &v.LogClientIP, &v.DHCPLeaseFile, &v.DiscoveryInterval,
		&v.HealthInterval, &v.HealthTimeout, &v.HealthWorkers)
	if errors.Is(err, sql.ErrNoRows) {
		return Settings{}, false, nil
	}
	if err != nil {
		return Settings{}, false, err
	}
	v.ReverseZones, v.Upstreams, v.AllowQuery = unpackList(rz), unpackList(up), unpackList(aq)
	return v, true, nil
}

// PutSettings writes the single row. Callers validate first: this is storage,
// not policy.
func (s *Store) PutSettings(v Settings) error {
	return putSettings(s.db, v)
}

// execer is the shared slice of *sql.DB and *sql.Tx, so the settings write can
// stand alone or join a larger transaction.
type execer interface {
	Exec(string, ...any) (sql.Result, error)
}

func putSettings(db execer, v Settings) error {
	_, err := db.Exec(`
INSERT INTO settings (id, private_domain, reverse_zones, upstreams, allow_query,
  allow_tailscale, ttl, cache_min_ttl, cache_max_ttl, negative_max_ttl,
  cache_entries, log_queries, log_client_ip, dhcp_lease_file,
  discovery_interval, health_interval, health_timeout, health_workers)
VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  private_domain=excluded.private_domain, reverse_zones=excluded.reverse_zones,
  upstreams=excluded.upstreams, allow_query=excluded.allow_query,
  allow_tailscale=excluded.allow_tailscale, ttl=excluded.ttl,
  cache_min_ttl=excluded.cache_min_ttl, cache_max_ttl=excluded.cache_max_ttl,
  negative_max_ttl=excluded.negative_max_ttl, cache_entries=excluded.cache_entries,
  log_queries=excluded.log_queries, log_client_ip=excluded.log_client_ip,
  dhcp_lease_file=excluded.dhcp_lease_file,
  discovery_interval=excluded.discovery_interval,
  health_interval=excluded.health_interval, health_timeout=excluded.health_timeout,
  health_workers=excluded.health_workers`,
		v.PrivateDomain, packList(v.ReverseZones), packList(v.Upstreams),
		packList(v.AllowQuery), v.AllowTailscale, v.TTL, v.CacheMinTTL,
		v.CacheMaxTTL, v.NegativeMaxTTL, v.CacheEntries, v.LogQueries,
		v.LogClientIP, v.DHCPLeaseFile, v.DiscoveryInterval, v.HealthInterval,
		v.HealthTimeout, v.HealthWorkers)
	return err
}

// ZoneSuffix normalizes a private domain into the form record names are stored
// in: lowercase, with exactly one trailing dot. An empty domain stays empty.
func ZoneSuffix(domain string) string {
	d := strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	if d == "" {
		return ""
	}
	return d + "."
}

// RenameInZone moves a name from one zone into another. It reports false for a
// name that was never inside from, which callers leave untouched: a record
// pointing outside the private zone is the operator's, not ours to rewrite.
func RenameInZone(name, from, to string) (string, bool) {
	if from == "" || to == "" || from == to {
		return name, false
	}
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return name, false
	}
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	switch {
	case n == from:
		return to, true
	case strings.HasSuffix(n, "."+from):
		return strings.TrimSuffix(n, from) + to, true
	}
	return name, false
}

// PutSettingsRenamingZone writes v and moves every manual record from the old
// private zone into the new one in a single transaction. Doing both at once is
// the point: a rename that half-applied would leave records answering for a
// zone the server no longer serves, with no way back except re-authoring them.
// It returns how many records moved.
func (s *Store) PutSettingsRenamingZone(v Settings, from, to string) (int, error) {
	from, to = ZoneSuffix(from), ZoneSuffix(to)
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := putSettings(tx, v); err != nil {
		return 0, err
	}

	// Read every record out before updating any: one transaction cannot hold an
	// open cursor and write through it.
	rows, err := tx.Query(`SELECT id, name, type, value FROM records`)
	if err != nil {
		return 0, err
	}
	var recs []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Value); err != nil {
			rows.Close()
			return 0, err
		}
		recs = append(recs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	moved := 0
	for _, r := range recs {
		name, nameMoved := RenameInZone(r.Name, from, to)
		value := r.Value
		valueMoved := false
		// A CNAME or PTR value is itself a name. One left pointing at the old
		// zone would resolve to nothing.
		if r.Type == "CNAME" || r.Type == "PTR" {
			value, valueMoved = RenameInZone(r.Value, from, to)
		}
		if !nameMoved && !valueMoved {
			continue
		}
		if _, err := tx.Exec(`UPDATE records SET name = ?, value = ? WHERE id = ?`, name, value, r.ID); err != nil {
			return 0, err
		}
		moved++
	}
	return moved, tx.Commit()
}
