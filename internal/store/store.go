// Package store owns all SQL. Every write in KyDNS passes through here, which
// is where the replication change log will later hook in.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrDuplicateCIDR = errors.New("cidr already claimed by another view")
	ErrViewInUse     = errors.New("view is referenced by an address or record")
	ErrDuplicateName = errors.New("name already exists")
)

type Store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS views (
  name       TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS view_subnets (
  view_name TEXT NOT NULL REFERENCES views(name) ON DELETE CASCADE,
  cidr      TEXT NOT NULL,
  PRIMARY KEY (view_name, cidr)
);
-- A CIDR may be claimed by only one view; equal-length overlapping prefixes
-- are the same network, so uniqueness is the whole ambiguity check.
CREATE UNIQUE INDEX IF NOT EXISTS idx_view_subnets_cidr ON view_subnets(cidr);
CREATE TABLE IF NOT EXISTS services (
  id              INTEGER PRIMARY KEY,
  name            TEXT NOT NULL UNIQUE,
  check_url       TEXT NOT NULL DEFAULT '',
  check_insecure  INTEGER NOT NULL DEFAULT 0,
  proxy_address   TEXT NOT NULL DEFAULT '',
  route_via_proxy INTEGER NOT NULL DEFAULT 0,
  mac             TEXT NOT NULL DEFAULT '',
  created_at      INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS service_addresses (
  id         INTEGER PRIMARY KEY,
  service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  address    TEXT NOT NULL,
  view_name  TEXT REFERENCES views(name)
);
CREATE TABLE IF NOT EXISTS aliases (
  id         INTEGER PRIMARY KEY,
  service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name       TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS records (
  id        INTEGER PRIMARY KEY,
  name      TEXT NOT NULL,
  type      TEXT NOT NULL,
  value     TEXT NOT NULL,
  view_name TEXT REFERENCES views(name)
);
CREATE TABLE IF NOT EXISTS tokens (
  id           INTEGER PRIMARY KEY,
  label        TEXT NOT NULL,
  hash         TEXT NOT NULL UNIQUE,
  created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  last_used_at INTEGER NOT NULL DEFAULT 0
);
-- The CHECK makes a second admin account impossible at the schema level.
CREATE TABLE IF NOT EXISTS admin (
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  password_hash TEXT NOT NULL,
  sso_sub       TEXT NOT NULL DEFAULT '',
  sso_username  TEXT NOT NULL DEFAULT '',
  sso_email     TEXT NOT NULL DEFAULT '',
  sso_linked_at INTEGER NOT NULL DEFAULT 0,
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS sso_settings (
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  enabled       INTEGER NOT NULL DEFAULT 0,
  issuer_url    TEXT NOT NULL DEFAULT '',
  client_id     TEXT NOT NULL DEFAULT 'kydns',
  client_secret TEXT NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO sso_settings(id, enabled, issuer_url, client_id, client_secret)
  VALUES(1, 0, 'https://auth.urlxl.com', 'kydns', '');
CREATE TABLE IF NOT EXISTS blacklist_settings (
  id        INTEGER PRIMARY KEY CHECK (id = 1),
  enabled   INTEGER NOT NULL DEFAULT 1,
  block_ttl INTEGER NOT NULL DEFAULT 60
);
INSERT OR IGNORE INTO blacklist_settings(id, enabled, block_ttl) VALUES(1, 1, 60);
CREATE TABLE IF NOT EXISTS blacklist_lists (
  id               INTEGER PRIMARY KEY,
  name             TEXT NOT NULL UNIQUE,
  url              TEXT NOT NULL,
  format           TEXT NOT NULL DEFAULT 'domains',
  description      TEXT NOT NULL DEFAULT '',
  enabled          INTEGER NOT NULL DEFAULT 1,
  builtin          INTEGER NOT NULL DEFAULT 0,
  interval_seconds INTEGER NOT NULL DEFAULT 86400,
  last_attempt_at  INTEGER NOT NULL DEFAULT 0,
  last_ok_at       INTEGER NOT NULL DEFAULT 0,
  last_error       TEXT NOT NULL DEFAULT '',
  etag             TEXT NOT NULL DEFAULT '',
  last_modified    TEXT NOT NULL DEFAULT '',
  entry_count      INTEGER NOT NULL DEFAULT 0,
  skipped_count    INTEGER NOT NULL DEFAULT 0,
  snapshot         TEXT NOT NULL DEFAULT ''
);
-- One rule per domain: a domain that is both allowed and denied is refused
-- here rather than by a check some caller could skip.
CREATE TABLE IF NOT EXISTS blacklist_rules (
  id     INTEGER PRIMARY KEY,
  kind   TEXT NOT NULL,
  domain TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS settings (
  id                 INTEGER PRIMARY KEY CHECK (id = 1),
  private_domain     TEXT NOT NULL,
  reverse_zones      TEXT NOT NULL,
  upstreams          TEXT NOT NULL,
  allow_query        TEXT NOT NULL,
  allow_tailscale    INTEGER NOT NULL,
  ttl                INTEGER NOT NULL,
  cache_min_ttl      INTEGER NOT NULL,
  cache_max_ttl      INTEGER NOT NULL,
  negative_max_ttl   INTEGER NOT NULL,
  cache_entries      INTEGER NOT NULL,
  log_queries        INTEGER NOT NULL,
  log_client_ip      INTEGER NOT NULL,
  dhcp_lease_file    TEXT NOT NULL,
  discovery_interval INTEGER NOT NULL,
  health_interval    INTEGER NOT NULL,
  health_timeout     INTEGER NOT NULL,
  health_workers     INTEGER NOT NULL,
  dhcp_enabled       INTEGER NOT NULL DEFAULT 0,
  dhcp_interface     TEXT NOT NULL DEFAULT '',
  dhcp_range_start   TEXT NOT NULL DEFAULT '',
  dhcp_range_end     TEXT NOT NULL DEFAULT '',
  dhcp_gateway       TEXT NOT NULL DEFAULT '',
  dhcp_lease_seconds INTEGER NOT NULL DEFAULT 86400,
  dhcp_secondary_dns TEXT NOT NULL DEFAULT '',
  dhcp_allow_foreign INTEGER NOT NULL DEFAULT 0
);
-- Node-local: no config_version trigger. A lease is this node's own DHCP
-- state, never a peer's, same as the tables below.
CREATE TABLE IF NOT EXISTS dhcp_leases (
  mac        TEXT PRIMARY KEY,
  ip         TEXT NOT NULL UNIQUE,
  hostname   TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS config_version (
  id      INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO config_version(id, version) VALUES(1, 0);
-- config_version is bumped by triggers rather than by Go, so a write path
-- added later cannot forget to bump it. The WHEN clauses on the UPDATE
-- triggers ARE the replicated settings split: anything absent is node-local
-- and deliberately invisible to replicas.
CREATE TRIGGER IF NOT EXISTS cv_views_i AFTER INSERT ON views BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_views_d AFTER DELETE ON views BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_view_subnets_i AFTER INSERT ON view_subnets BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_view_subnets_d AFTER DELETE ON view_subnets BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_services_i AFTER INSERT ON services BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_services_u AFTER UPDATE ON services BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_services_d AFTER DELETE ON services BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_service_addresses_i AFTER INSERT ON service_addresses BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_service_addresses_u AFTER UPDATE ON service_addresses BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_service_addresses_d AFTER DELETE ON service_addresses BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_aliases_i AFTER INSERT ON aliases BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_aliases_d AFTER DELETE ON aliases BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_records_i AFTER INSERT ON records BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_records_u AFTER UPDATE ON records BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_records_d AFTER DELETE ON records BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_blacklist_settings_u AFTER UPDATE ON blacklist_settings BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_blacklist_rules_i AFTER INSERT ON blacklist_rules BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_blacklist_rules_u AFTER UPDATE ON blacklist_rules BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_blacklist_rules_d AFTER DELETE ON blacklist_rules BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
-- Definition columns only. A refresh writes snapshot, etag, last_modified and
-- the counters on every poll; those are node-local and must not look like a
-- configuration change.
CREATE TRIGGER IF NOT EXISTS cv_blacklist_lists_i AFTER INSERT ON blacklist_lists BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_blacklist_lists_d AFTER DELETE ON blacklist_lists BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_blacklist_lists_u AFTER UPDATE ON blacklist_lists
WHEN old.name IS NOT new.name
  OR old.url IS NOT new.url
  OR old.format IS NOT new.format
  OR old.description IS NOT new.description
  OR old.enabled IS NOT new.enabled
  OR old.builtin IS NOT new.builtin
  OR old.interval_seconds IS NOT new.interval_seconds
BEGIN UPDATE config_version SET version = version + 1 WHERE id = 1; END;
-- Replicated settings columns only. dhcp_lease_file, discovery_interval,
-- log_queries, log_client_ip and every dhcp_* column are absent on purpose:
-- they are node-local.
CREATE TRIGGER IF NOT EXISTS cv_settings_i AFTER INSERT ON settings BEGIN
  UPDATE config_version SET version = version + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS cv_settings_u AFTER UPDATE ON settings
WHEN old.private_domain IS NOT new.private_domain
  OR old.reverse_zones IS NOT new.reverse_zones
  OR old.upstreams IS NOT new.upstreams
  OR old.allow_query IS NOT new.allow_query
  OR old.allow_tailscale IS NOT new.allow_tailscale
  OR old.ttl IS NOT new.ttl
  OR old.cache_min_ttl IS NOT new.cache_min_ttl
  OR old.cache_max_ttl IS NOT new.cache_max_ttl
  OR old.negative_max_ttl IS NOT new.negative_max_ttl
  OR old.cache_entries IS NOT new.cache_entries
  OR old.health_interval IS NOT new.health_interval
  OR old.health_timeout IS NOT new.health_timeout
  OR old.health_workers IS NOT new.health_workers
BEGIN UPDATE config_version SET version = version + 1 WHERE id = 1; END;
-- Node-local trust anchors: no config_version trigger. A peer list must
-- never arrive from a peer.
CREATE TABLE IF NOT EXISTS peers (
  node_id      TEXT PRIMARY KEY,
  label        TEXT NOT NULL DEFAULT '',
  address      TEXT NOT NULL DEFAULT '',
  paired_at    INTEGER NOT NULL DEFAULT 0,
  last_sync_at INTEGER NOT NULL DEFAULT 0,
  last_version INTEGER NOT NULL DEFAULT 0
);
-- The primary's version as this replica last applied it. Node-local
-- bookkeeping, so no config_version trigger: this node's own counter moves
-- every time a snapshot lands and says nothing about the primary.
CREATE TABLE IF NOT EXISTS replica_state (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  primary_node_id TEXT NOT NULL DEFAULT '',
  last_version    INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO replica_state(id) VALUES(1);
-- A promotion is recorded here, never by rewriting replication.primary in the
-- operator's config file: KyDNS edits that file nowhere else, and a daemon
-- that started doing so would be a surprise. Startup reads this first, so a key still
-- sitting in the file loses to a promotion that actually happened. Node-local,
-- so no config_version trigger: a promotion is this node's own history.
CREATE TABLE IF NOT EXISTS promotion (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  promoted_at INTEGER NOT NULL
);
`

// migrations run in order on a database whose user_version is below their
// index+1. A fresh database gets everything from schema above and then skips
// straight to the end, because applying an ALTER to a column that is already
// there would fail.
var migrations = []string{
	`ALTER TABLE services ADD COLUMN proxy_address TEXT NOT NULL DEFAULT '';
	 ALTER TABLE services ADD COLUMN route_via_proxy INTEGER NOT NULL DEFAULT 0;`,
	`CREATE TABLE IF NOT EXISTS settings (
	   id                 INTEGER PRIMARY KEY CHECK (id = 1),
	   private_domain     TEXT NOT NULL,
	   reverse_zones      TEXT NOT NULL,
	   upstreams          TEXT NOT NULL,
	   allow_query        TEXT NOT NULL,
	   allow_tailscale    INTEGER NOT NULL,
	   ttl                INTEGER NOT NULL,
	   cache_min_ttl      INTEGER NOT NULL,
	   cache_max_ttl      INTEGER NOT NULL,
	   negative_max_ttl   INTEGER NOT NULL,
	   cache_entries      INTEGER NOT NULL,
	   log_queries        INTEGER NOT NULL,
	   log_client_ip      INTEGER NOT NULL,
	   dhcp_lease_file    TEXT NOT NULL,
	   discovery_interval INTEGER NOT NULL,
	   health_interval    INTEGER NOT NULL,
	   health_timeout     INTEGER NOT NULL,
	   health_workers     INTEGER NOT NULL
	 );`,
	`ALTER TABLE admin ADD COLUMN sso_sub TEXT NOT NULL DEFAULT '';
	 ALTER TABLE admin ADD COLUMN sso_username TEXT NOT NULL DEFAULT '';
	 ALTER TABLE admin ADD COLUMN sso_email TEXT NOT NULL DEFAULT '';
	 ALTER TABLE admin ADD COLUMN sso_linked_at INTEGER NOT NULL DEFAULT 0;
	 CREATE TABLE IF NOT EXISTS sso_settings (
	   id            INTEGER PRIMARY KEY CHECK (id = 1),
	   enabled       INTEGER NOT NULL DEFAULT 0,
	   issuer_url    TEXT NOT NULL DEFAULT '',
	   client_id     TEXT NOT NULL DEFAULT 'kydns',
	   client_secret TEXT NOT NULL DEFAULT ''
	 );
	 INSERT OR IGNORE INTO sso_settings(id, enabled, issuer_url, client_id, client_secret)
	   VALUES(1, 0, 'https://auth.urlxl.com', 'kydns', '');`,
	`ALTER TABLE settings ADD COLUMN dhcp_enabled INTEGER NOT NULL DEFAULT 0;
	 ALTER TABLE settings ADD COLUMN dhcp_interface TEXT NOT NULL DEFAULT '';
	 ALTER TABLE settings ADD COLUMN dhcp_range_start TEXT NOT NULL DEFAULT '';
	 ALTER TABLE settings ADD COLUMN dhcp_range_end TEXT NOT NULL DEFAULT '';
	 ALTER TABLE settings ADD COLUMN dhcp_gateway TEXT NOT NULL DEFAULT '';
	 ALTER TABLE settings ADD COLUMN dhcp_lease_seconds INTEGER NOT NULL DEFAULT 86400;
	 ALTER TABLE settings ADD COLUMN dhcp_secondary_dns TEXT NOT NULL DEFAULT '';
	 CREATE TABLE IF NOT EXISTS dhcp_leases (
	   mac        TEXT PRIMARY KEY,
	   ip         TEXT NOT NULL UNIQUE,
	   hostname   TEXT NOT NULL,
	   expires_at INTEGER NOT NULL,
	   last_seen  INTEGER NOT NULL
	 );`,
	`ALTER TABLE settings ADD COLUMN dhcp_allow_foreign INTEGER NOT NULL DEFAULT 0;`,
	`ALTER TABLE services ADD COLUMN mac TEXT NOT NULL DEFAULT '';`,
}

// migrate runs against a transaction Open already holds, so a crash
// partway through - whether mid-ALTER or mid-schema-creation - rolls back
// cleanly instead of leaving a database that wedges every future Open.
func migrate(tx *sql.Tx, freshDB bool) error {
	var version int
	if err := tx.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if freshDB {
		version = len(migrations)
	}
	if version >= len(migrations) {
		if !freshDB {
			return nil
		}
		// A fresh database already has the columns from schema, but still
		// needs user_version set so a later Open doesn't try to ALTER them in.
		_, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations)))
		return err
	}
	for i := version; i < len(migrations); i++ {
		for _, stmt := range strings.Split(migrations[i], ";") {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, err := tx.Exec(stmt); err != nil {
				if !strings.Contains(err.Error(), "duplicate column name") {
					return fmt.Errorf("migration %d: %w", i+1, err)
				}
			}
		}
	}
	_, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations)))
	return err
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// One writer, so a single connection avoids SQLITE_BUSY entirely.
	db.SetMaxOpenConns(1)
	for _, p := range []string{
		"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA synchronous=NORMAL",
	} {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}

	// A database with no services table has never been written by KyDNS, so
	// the schema below creates everything and no migration should run.
	var n int
	if err := db.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='services'`).Scan(&n); err != nil {
		db.Close()
		return nil, err
	}
	fresh := n == 0

	// Schema creation and the migration bookkeeping run in one transaction,
	// so a crash partway through leaves nothing behind instead of a
	// half-built database that wedges every future Open.
	tx, err := db.Begin()
	if err != nil {
		db.Close()
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	if err := migrate(tx, fresh); err != nil {
		db.Close()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func isUnique(err error, fragment string) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE") && strings.Contains(err.Error(), fragment)
}

// PutView inserts or replaces a view and its subnets atomically.
func (s *Store) PutView(v View) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := putView(tx, v); err != nil {
		return err
	}
	return tx.Commit()
}

// putView does the work of PutView against an already-open transaction, so
// ReplaceAll can write many views as part of one larger transaction.
func putView(tx *sql.Tx, v View) error {
	if _, err := tx.Exec(`INSERT OR IGNORE INTO views(name) VALUES(?)`, v.Name); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM view_subnets WHERE view_name = ?`, v.Name); err != nil {
		return err
	}
	for _, c := range v.Subnets {
		if _, err := tx.Exec(`INSERT INTO view_subnets(view_name, cidr) VALUES(?, ?)`, v.Name, c); err != nil {
			if isUnique(err, "view_subnets.cidr") {
				return fmt.Errorf("%w: %s", ErrDuplicateCIDR, c)
			}
			return err
		}
	}
	return nil
}

func (s *Store) Views() ([]View, error) {
	rows, err := s.db.Query(`
		SELECT v.name, COALESCE(sn.cidr, '')
		FROM views v LEFT JOIN view_subnets sn ON sn.view_name = v.name
		ORDER BY v.name, sn.cidr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []View
	byName := map[string]int{}
	for rows.Next() {
		var name, cidr string
		if err := rows.Scan(&name, &cidr); err != nil {
			return nil, err
		}
		i, ok := byName[name]
		if !ok {
			out = append(out, View{Name: name})
			i = len(out) - 1
			byName[name] = i
		}
		if cidr != "" {
			out[i].Subnets = append(out[i].Subnets, cidr)
		}
	}
	return out, rows.Err()
}

func (s *Store) DeleteView(name string) error {
	var n int
	if err := s.db.QueryRow(`
		SELECT (SELECT COUNT(*) FROM service_addresses WHERE view_name = ?) +
		       (SELECT COUNT(*) FROM records WHERE view_name = ?)`, name, name).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: %s (%d references)", ErrViewInUse, name, n)
	}
	res, err := s.db.Exec(`DELETE FROM views WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: view %s", ErrNotFound, name)
	}
	return nil
}

// PutService inserts a new service or replaces an existing one by ID,
// rewriting its addresses and aliases in one transaction.
func (s *Store) PutService(svc Service) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	id, err := putService(tx, svc)
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// putService does the work of PutService against an already-open
// transaction, so ReplaceAll can write many services as part of one larger
// transaction.
func putService(tx *sql.Tx, svc Service) (int64, error) {
	if svc.ID == 0 {
		res, err := tx.Exec(
			`INSERT INTO services(name, check_url, check_insecure, proxy_address, route_via_proxy, mac) VALUES(?, ?, ?, ?, ?, ?)`,
			svc.Name, svc.CheckURL, svc.CheckInsecure, svc.ProxyAddress, svc.RouteViaProxy, svc.MAC)
		if err != nil {
			if isUnique(err, "services.name") {
				return 0, fmt.Errorf("%w: service %s", ErrDuplicateName, svc.Name)
			}
			return 0, err
		}
		if svc.ID, err = res.LastInsertId(); err != nil {
			return 0, err
		}
	} else {
		if _, err := tx.Exec(
			`UPDATE services SET name=?, check_url=?, check_insecure=?, proxy_address=?, route_via_proxy=?, mac=? WHERE id=?`,
			svc.Name, svc.CheckURL, svc.CheckInsecure, svc.ProxyAddress, svc.RouteViaProxy, svc.MAC, svc.ID); err != nil {
			return 0, err
		}
		for _, q := range []string{
			`DELETE FROM service_addresses WHERE service_id = ?`,
			`DELETE FROM aliases WHERE service_id = ?`,
		} {
			if _, err := tx.Exec(q, svc.ID); err != nil {
				return 0, err
			}
		}
	}
	for _, a := range svc.Addresses {
		if _, err := tx.Exec(`INSERT INTO service_addresses(service_id, address, view_name) VALUES(?, ?, ?)`,
			svc.ID, a.Address, nullable(a.View)); err != nil {
			return 0, err
		}
	}
	for _, al := range svc.Aliases {
		if _, err := tx.Exec(`INSERT INTO aliases(service_id, name) VALUES(?, ?)`, svc.ID, al); err != nil {
			if isUnique(err, "aliases.name") {
				return 0, fmt.Errorf("%w: alias %s", ErrDuplicateName, al)
			}
			return 0, err
		}
	}
	return svc.ID, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Store) Service(id int64) (Service, error) {
	var svc Service
	err := s.db.QueryRow(
		`SELECT id, name, check_url, check_insecure, proxy_address, route_via_proxy, mac FROM services WHERE id = ?`, id).
		Scan(&svc.ID, &svc.Name, &svc.CheckURL, &svc.CheckInsecure, &svc.ProxyAddress, &svc.RouteViaProxy, &svc.MAC)
	if errors.Is(err, sql.ErrNoRows) {
		return Service{}, fmt.Errorf("%w: service %d", ErrNotFound, id)
	}
	if err != nil {
		return Service{}, err
	}
	if svc.Addresses, err = s.addresses(svc.ID); err != nil {
		return Service{}, err
	}
	if svc.Aliases, err = s.aliases(svc.ID); err != nil {
		return Service{}, err
	}
	return svc, nil
}

func (s *Store) addresses(serviceID int64) ([]Address, error) {
	rows, err := s.db.Query(
		`SELECT id, address, COALESCE(view_name, '') FROM service_addresses WHERE service_id = ? ORDER BY id`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Address
	for rows.Next() {
		var a Address
		if err := rows.Scan(&a.ID, &a.Address, &a.View); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) aliases(serviceID int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT name FROM aliases WHERE service_id = ? ORDER BY name`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// Services returns every service with addresses and aliases loaded. The
// snapshot builder is the main caller, so IDs are collected in one pass first.
func (s *Store) Services() ([]Service, error) {
	rows, err := s.db.Query(`SELECT id FROM services ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Service, 0, len(ids))
	for _, id := range ids {
		svc, err := s.Service(id)
		if err != nil {
			return nil, err
		}
		out = append(out, svc)
	}
	return out, nil
}

func (s *Store) DeleteService(id int64) error {
	res, err := s.db.Exec(`DELETE FROM services WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: service %d", ErrNotFound, id)
	}
	return nil
}

func (s *Store) PutRecord(r Record) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	id, err := putRecord(tx, r)
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// putRecord does the work of PutRecord against an already-open transaction,
// so ReplaceAll can write many records as part of one larger transaction.
func putRecord(tx *sql.Tx, r Record) (int64, error) {
	res, err := tx.Exec(`INSERT INTO records(name, type, value, view_name) VALUES(?, ?, ?, ?)`,
		r.Name, r.Type, r.Value, nullable(r.View))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) Records() ([]Record, error) {
	rows, err := s.db.Query(
		`SELECT id, name, type, value, COALESCE(view_name, '') FROM records ORDER BY name, type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Value, &r.View); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteRecord(id int64) error {
	res, err := s.db.Exec(`DELETE FROM records WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: record %d", ErrNotFound, id)
	}
	return nil
}

// SetAdminPassword writes the single admin row.
func (s *Store) SetAdminPassword(hash string) error {
	_, err := s.db.Exec(`
		INSERT INTO admin(id, password_hash, updated_at) VALUES(1, ?, unixepoch())
		ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash,
		                              updated_at = excluded.updated_at`, hash)
	return err
}

func (s *Store) AdminHash() (string, error) {
	var hash string
	err := s.db.QueryRow(`SELECT password_hash FROM admin WHERE id = 1`).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: admin account", ErrNotFound)
	}
	return hash, err
}

func (s *Store) AdminIdentity() (*AdminIdentity, error) {
	var a AdminIdentity
	err := s.db.QueryRow(`
		SELECT password_hash, sso_sub, sso_username, sso_email, sso_linked_at, updated_at
		FROM admin WHERE id = 1
	`).Scan(&a.PasswordHash, &a.SSOSub, &a.SSOUsername, &a.SSOEmail, &a.SSOLinkedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: admin account", ErrNotFound)
	}
	return &a, err
}

func (s *Store) LinkAdminSSO(sub, username, email string) error {
	res, err := s.db.Exec(`
		UPDATE admin
		SET sso_sub = ?, sso_username = ?, sso_email = ?, sso_linked_at = unixepoch(), updated_at = unixepoch()
		WHERE id = 1
	`, sub, username, email)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: admin account", ErrNotFound)
	}
	return nil
}

func (s *Store) UnlinkAdminSSO() error {
	res, err := s.db.Exec(`
		UPDATE admin
		SET sso_sub = '', sso_username = '', sso_email = '', sso_linked_at = 0, updated_at = unixepoch()
		WHERE id = 1
	`)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: admin account", ErrNotFound)
	}
	return nil
}

func (s *Store) SSOSettings() (SSOSettings, error) {
	var sso SSOSettings
	var enabled int
	err := s.db.QueryRow(`SELECT enabled, issuer_url, client_id, client_secret FROM sso_settings WHERE id = 1`).
		Scan(&enabled, &sso.IssuerURL, &sso.ClientID, &sso.ClientSecret)
	if errors.Is(err, sql.ErrNoRows) {
		return SSOSettings{Enabled: false, IssuerURL: "https://auth.urlxl.com", ClientID: "kydns"}, nil
	}
	sso.Enabled = enabled == 1
	return sso, err
}

func (s *Store) SetSSOSettings(sso SSOSettings) error {
	enabledInt := 0
	if sso.Enabled {
		enabledInt = 1
	}
	_, err := s.db.Exec(`
		INSERT INTO sso_settings(id, enabled, issuer_url, client_id, client_secret)
		VALUES(1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			enabled = excluded.enabled,
			issuer_url = excluded.issuer_url,
			client_id = excluded.client_id,
			client_secret = excluded.client_secret
	`, enabledInt, sso.IssuerURL, sso.ClientID, sso.ClientSecret)
	return err
}

func (s *Store) HasAdmin() (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM admin WHERE id = 1`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *Store) PutToken(t Token) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO tokens(label, hash) VALUES(?, ?)`, t.Label, t.Hash)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) Tokens() ([]Token, error) {
	rows, err := s.db.Query(`SELECT id, label, hash, created_at, last_used_at FROM tokens ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.Label, &t.Hash, &t.CreatedAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) TouchToken(id int64) error {
	_, err := s.db.Exec(`UPDATE tokens SET last_used_at = unixepoch() WHERE id = ?`, id)
	return err
}

func (s *Store) DeleteToken(id int64) error {
	res, err := s.db.Exec(`DELETE FROM tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: token %d", ErrNotFound, id)
	}
	return nil
}

// ReplaceAll wipes registry data and writes the given contents in one
// transaction, for import --replace. A failure partway through — a duplicate
// name, a claimed CIDR — rolls back the wipe too, so a bad document leaves
// the prior registry untouched rather than half-restored. Tokens and the
// admin account survive: an import must never lock the operator out.
func (s *Store) ReplaceAll(views []View, services []Service, records []Record) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := replaceAll(tx, views, services, records); err != nil {
		return err
	}
	return tx.Commit()
}

// replaceAll does the work of ReplaceAll against an already-open transaction,
// so ApplySnapshot can write the registry as part of one larger transaction.
func replaceAll(tx *sql.Tx, views []View, services []Service, records []Record) error {
	for _, q := range []string{
		`DELETE FROM records`, `DELETE FROM aliases`,
		`DELETE FROM service_addresses`, `DELETE FROM services`,
		`DELETE FROM view_subnets`, `DELETE FROM views`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	for _, v := range views {
		if err := putView(tx, v); err != nil {
			return err
		}
	}
	for _, svc := range services {
		svc.ID = 0
		if _, err := putService(tx, svc); err != nil {
			return err
		}
	}
	for _, r := range records {
		r.ID = 0
		if _, err := putRecord(tx, r); err != nil {
			return err
		}
	}
	return nil
}

// SnapshotInput is a primary's replicated configuration, as pulled by a
// replica and applied with ApplySnapshot.
type SnapshotInput struct {
	Views     []View
	Services  []Service
	Records   []Record
	Settings  Settings
	Blacklist BlacklistSettings
	Lists     []BlacklistList
	Rules     []BlacklistRule
}

// ApplySnapshot replaces all replicated state in one transaction. A replica
// applying a bad document must be left exactly as it was, so nothing here is
// allowed to commit independently. Tokens, the admin account, and list
// bodies are node-local and untouched.
func (s *Store) ApplySnapshot(in SnapshotInput) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := replaceAll(tx, in.Views, in.Services, in.Records); err != nil {
		return err
	}
	// dhcp_lease_file, discovery_interval, log_queries, log_client_ip and every
	// dhcp_* column are node-local and never replicated. Enforced here rather
	// than trusted to the caller, so a later caller that forwards a pulled
	// Settings verbatim cannot wipe them out.
	settings := in.Settings
	var dhcpLeaseFile, dhcpInterface, dhcpRangeStart, dhcpRangeEnd, dhcpGateway, dhcpSecondaryDNS string
	var discoveryInterval, dhcpLeaseSeconds int
	var logQueries, logClientIP, dhcpEnabled, dhcpAllowForeign bool
	err = tx.QueryRow(`
SELECT dhcp_lease_file, discovery_interval, log_queries, log_client_ip,
       dhcp_enabled, dhcp_interface, dhcp_range_start, dhcp_range_end,
       dhcp_gateway, dhcp_lease_seconds, dhcp_secondary_dns, dhcp_allow_foreign
FROM settings WHERE id = 1`).
		Scan(&dhcpLeaseFile, &discoveryInterval, &logQueries, &logClientIP,
			&dhcpEnabled, &dhcpInterface, &dhcpRangeStart, &dhcpRangeEnd,
			&dhcpGateway, &dhcpLeaseSeconds, &dhcpSecondaryDNS, &dhcpAllowForeign)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		settings.DHCPLeaseFile, settings.DiscoveryInterval = dhcpLeaseFile, discoveryInterval
		settings.LogQueries, settings.LogClientIP = logQueries, logClientIP
		settings.DHCPEnabled, settings.DHCPInterface = dhcpEnabled, dhcpInterface
		settings.DHCPRangeStart, settings.DHCPRangeEnd = dhcpRangeStart, dhcpRangeEnd
		settings.DHCPGateway, settings.DHCPLeaseSeconds = dhcpGateway, dhcpLeaseSeconds
		settings.DHCPSecondaryDNS, settings.DHCPAllowForeign = dhcpSecondaryDNS, dhcpAllowForeign
	}
	if err := putSettings(tx, settings); err != nil {
		return err
	}
	if err := replaceBlacklistDefinitions(tx, in.Blacklist, in.Lists, in.Rules); err != nil {
		return err
	}
	return tx.Commit()
}
