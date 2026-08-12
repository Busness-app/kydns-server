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
  updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
);
`

// migrations run in order on a database whose user_version is below their
// index+1. A fresh database gets everything from schema above and then skips
// straight to the end, because applying an ALTER to a column that is already
// there would fail.
var migrations = []string{
	`ALTER TABLE services ADD COLUMN proxy_address TEXT NOT NULL DEFAULT '';
	 ALTER TABLE services ADD COLUMN route_via_proxy INTEGER NOT NULL DEFAULT 0;`,
}

func migrate(db *sql.DB, freshDB bool) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
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
		_, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations)))
		return err
	}

	// A crash between an ALTER and the user_version bump must not leave a
	// database that fails every future Open, so both run in one transaction.
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i := version; i < len(migrations); i++ {
		if _, err := tx.Exec(migrations[i]); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations))); err != nil {
		return err
	}
	return tx.Commit()
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

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	if err := migrate(db, fresh); err != nil {
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
			`INSERT INTO services(name, check_url, check_insecure, proxy_address, route_via_proxy) VALUES(?, ?, ?, ?, ?)`,
			svc.Name, svc.CheckURL, svc.CheckInsecure, svc.ProxyAddress, svc.RouteViaProxy)
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
			`UPDATE services SET name=?, check_url=?, check_insecure=?, proxy_address=?, route_via_proxy=? WHERE id=?`,
			svc.Name, svc.CheckURL, svc.CheckInsecure, svc.ProxyAddress, svc.RouteViaProxy, svc.ID); err != nil {
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
		`SELECT id, name, check_url, check_insecure, proxy_address, route_via_proxy FROM services WHERE id = ?`, id).
		Scan(&svc.ID, &svc.Name, &svc.CheckURL, &svc.CheckInsecure, &svc.ProxyAddress, &svc.RouteViaProxy)
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
	return tx.Commit()
}
