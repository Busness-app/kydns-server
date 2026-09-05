package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalSettingsAndAuditSurviveSnapshotApply(t *testing.T) {
	s := open(t)
	if err := s.SetLocalSetting("kyrecovery_token", "sealed"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAudit(AuditEvent{Actor: "admin", Action: "backup.paired", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplySnapshot(SnapshotInput{Settings: baseSettings()}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetLocalSetting("kyrecovery_token"); err != nil || got != "sealed" {
		t.Fatalf("local setting after apply = %q, %v", got, err)
	}
}

func TestLocalSettingNotFound(t *testing.T) {
	if _, err := open(t).GetLocalSetting("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestSnapshotIncludesCommittedWALData(t *testing.T) {
	s := open(t)
	if _, err := s.PutService(Service{Name: "uncheckpointed"}); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "snapshot.db")
	if err := s.SnapshotTo(dst); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("snapshot mode = %o, want 600", info.Mode().Perm())
	}
	copy, err := Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	services, err := copy.Services()
	if err != nil || len(services) != 1 || services[0].Name != "uncheckpointed" {
		t.Fatalf("snapshot services = %+v, %v", services, err)
	}
}

func TestSnapshotPathIsBoundNotInterpolated(t *testing.T) {
	s := open(t)
	dst := filepath.Join(t.TempDir(), "snapshot'; PRAGMA user_version=999; --.db")
	if err := s.SnapshotTo(dst); err != nil {
		t.Fatal(err)
	}
	if version := userVersion(t, s.db); version != len(migrations) {
		t.Fatalf("user_version = %d, want %d", version, len(migrations))
	}
}

func userVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}
