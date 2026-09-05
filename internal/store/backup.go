package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
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
	if _, err := s.db.Exec(`VACUUM INTO ?`, path); err != nil {
		return fmt.Errorf("snapshot database: %w", err)
	}
	return nil
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
