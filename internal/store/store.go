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
  id             INTEGER PRIMARY KEY,
  name           TEXT NOT NULL UNIQUE,
  check_url      TEXT NOT NULL DEFAULT '',
  check_insecure INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL DEFAULT (unixepoch())
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
`

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
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
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
	return tx.Commit()
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
	if svc.ID == 0 {
		res, err := tx.Exec(`INSERT INTO services(name, check_url, check_insecure) VALUES(?, ?, ?)`,
			svc.Name, svc.CheckURL, svc.CheckInsecure)
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
		if _, err := tx.Exec(`UPDATE services SET name=?, check_url=?, check_insecure=? WHERE id=?`,
			svc.Name, svc.CheckURL, svc.CheckInsecure, svc.ID); err != nil {
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
	return svc.ID, tx.Commit()
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Store) Service(id int64) (Service, error) {
	var svc Service
	err := s.db.QueryRow(`SELECT id, name, check_url, check_insecure FROM services WHERE id = ?`, id).
		Scan(&svc.ID, &svc.Name, &svc.CheckURL, &svc.CheckInsecure)
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
	res, err := s.db.Exec(`INSERT INTO records(name, type, value, view_name) VALUES(?, ?, ?, ?)`,
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
