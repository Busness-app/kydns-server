package store

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenSnapshotReadsWithoutWriting(t *testing.T) {
	s := open(t)
	if err := s.SetLocalSetting("sentinel", "preserved"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.db")
	if err := s.SnapshotTo(path); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	copy, err := OpenSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := copy.GetLocalSetting("sentinel"); err != nil || got != "preserved" {
		t.Fatalf("read = %q, %v", got, err)
	}
	if err := copy.SetLocalSetting("sentinel", "overwritten"); err == nil {
		t.Fatal("snapshot allowed a write")
	}
	if err := copy.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("snapshot was modified")
	}
	missing := filepath.Join(t.TempDir(), "missing.db")
	if _, err := OpenSnapshot(missing); err == nil {
		t.Fatal("opened absent database")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created absent database")
	}
}

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

func TestVerifySnapshotRefusesWhatIsNotAKyDNSDatabase(t *testing.T) {
	s := open(t)
	dst := filepath.Join(t.TempDir(), "snapshot.db")
	if err := s.SnapshotTo(dst); err != nil {
		t.Fatal(err)
	}
	if err := VerifySnapshot(dst); err != nil {
		t.Fatalf("VerifySnapshot(good) = %v", err)
	}
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.db")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(dir, "junk.db")
	if err := os.WriteFile(junk, make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(dir, "foreign.db")
	db, err := sql.Open("sqlite", foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE unrelated (id INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{empty, junk, foreign, filepath.Join(dir, "absent.db")} {
		if err := VerifySnapshot(path); err == nil {
			t.Errorf("VerifySnapshot(%s) accepted", filepath.Base(path))
		}
	}
	// Verifying must not conjure the file it was asked about.
	if _, err := os.Stat(filepath.Join(dir, "absent.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent.db after verify: %v", err)
	}
}
