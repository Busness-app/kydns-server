package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"github.com/Busness-app/ky-primitives/recoveryclient"
)

type AuditEvent struct {
	Actor, Action, Resource, Details, IP, Outcome string
}

func (s *Store) GetLocalSetting(key string) (string, error) {
	var value string
	if err := s.db.QueryRow(`SELECT value FROM local_settings WHERE key = ?`, key).Scan(&value); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return value, nil
}

func (s *Store) SetLocalSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO local_settings(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *Store) DeleteLocalSetting(key string) error {
	_, err := s.db.Exec(`DELETE FROM local_settings WHERE key = ?`, key)
	return err
}

func (s *Store) RecordAudit(e AuditEvent) error {
	_, err := s.db.Exec(`INSERT INTO audit_events(actor, action, resource, details, ip, outcome)
		VALUES(?, ?, ?, ?, ?, ?)`, e.Actor, e.Action, e.Resource, e.Details, e.IP, e.Outcome)
	return err
}

// SnapshotTo creates a transactionally consistent SQLite copy through the live handle.
func (s *Store) SnapshotTo(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("snapshot path must be absolute")
	}
	return recoveryclient.SQLiteSnapshot(context.Background(), s.db, path)
}

func (s *Store) IntegrityCheck() error {
	var result string
	if err := s.db.QueryRow(`PRAGMA integrity_check`).Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("sqlite integrity check: %s", result)
	}
	return nil
}

// sqliteHeader is the magic every SQLite database starts with. A zero-length file is a
// valid empty database to SQLite and any open would create the schema in it, so the
// magic, not a successful open, is what tells a real snapshot from a truncated one.
const sqliteHeader = "SQLite format 3\x00"

// OpenSnapshot opens a verified artifact read-only, without migrations or defaults.
// Callers own Close; even the Store's write methods cannot change this connection.
func OpenSnapshot(path string) (*Store, error) {
	if err := VerifySnapshot(path); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: abs, RawQuery: "mode=ro"}).String())
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// VerifySnapshot reports whether path holds an intact KyDNS database. It opens read-only
// and never creates or migrates: the file is an artifact under test, not this node's store.
func VerifySnapshot(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	f, err := os.Open(abs)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	head := make([]byte, len(sqliteHeader))
	if _, err := io.ReadFull(f, head); err != nil || info.Size() < 100 || string(head) != sqliteHeader {
		return fmt.Errorf("%s is not a SQLite database (%d bytes)", filepath.Base(abs), info.Size())
	}
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: abs, RawQuery: "mode=ro"}).String())
	if err != nil {
		return err
	}
	defer db.Close()
	var result string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("sqlite integrity check: %s", result)
	}
	var tables int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master
		WHERE type = 'table' AND name IN ('services', 'local_settings')`).Scan(&tables); err != nil {
		return err
	}
	if tables < 2 {
		return fmt.Errorf("%s is not a KyDNS database", filepath.Base(abs))
	}
	return nil
}
