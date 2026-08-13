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
	_, err := s.db.Exec(`
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
