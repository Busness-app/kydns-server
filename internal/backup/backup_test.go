package backup

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kydns-server/internal/config"
	"github.com/Busness-app/kydns-server/internal/store"
	_ "modernc.org/sqlite"
)

func testService(t *testing.T, tweak func(*config.Config)) *Service {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := &config.Config{DataDir: dir, BackupKeep: 7, DNS: config.DNSConfig{Listen: ":53"}, Admin: config.AdminConfig{Listen: "127.0.0.1:8053"}}
	if tweak != nil {
		tweak(cfg)
	}
	s, err := New(cfg, st, "test")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func pinFresh(t *testing.T, s *Service) recoverykey.PrivateKey {
	t.Helper()
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(priv.Public().Bytes())
	if _, err := s.PinKey(b64, 2, 3); err != nil {
		t.Fatal(err)
	}
	return priv
}

// dumpLocalSettings concatenates every stored value, read back through a second
// connection so the test sees what is on disk rather than what the caller passed in.
func dumpLocalSettings(t *testing.T, s *Service) string {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(s.Cfg.DataDir, "kydns.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT key, value FROM local_settings`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out strings.Builder
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatal(err)
		}
		out.WriteString(k + "=" + v + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestPinByHandIsWriteOnce(t *testing.T) {
	s := testService(t, nil)
	pinFresh(t, s)
	other, _ := recoverykey.Generate()
	_, err := s.PinKey(base64.StdEncoding.EncodeToString(other.Public().Bytes()), 2, 3)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second pin error = %v, want fs.ErrExist", err)
	}
}

func TestPinnedKeyWithNoDestinationIsNoDestination(t *testing.T) {
	s := testService(t, nil)
	pinFresh(t, s)
	if _, err := s.Run(context.Background()); !errors.Is(err, recoveryclient.ErrNoDestination) {
		t.Fatalf("Run error = %v, want ErrNoDestination", err)
	}
}

func TestRunWritesALocalCopyOnlyKeyOpens(t *testing.T) {
	dir := t.TempDir()
	s := testService(t, func(c *config.Config) { c.BackupDir = dir; c.BackupKeep = 1 })
	priv := pinFresh(t, s)
	res, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(res.LocalPath), "KyDNS.") {
		t.Fatalf("local path %q lacks the KyDNS. prefix", res.LocalPath)
	}
	info, err := os.Stat(res.LocalPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	raw, err := os.ReadFile(res.LocalPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := capsule.Open(raw, priv, ""); err != nil {
		t.Fatal(err)
	}
	wrong, _ := recoverykey.Generate()
	if _, _, err := capsule.Open(raw, wrong, ""); !errors.Is(err, capsule.ErrWrongRecoveryKey) {
		t.Fatalf("wrong key error = %v", err)
	}
	// A second run prunes to keep=1 but leaves a foreign file alone.
	foreign := filepath.Join(dir, "Other-x.kycap")
	if err := os.WriteFile(foreign, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	copies, err := recoveryclient.ListLocalCopies(dir, ServiceName)
	if err != nil {
		t.Fatal(err)
	}
	if len(copies) != 1 {
		t.Fatalf("copies = %d, want 1", len(copies))
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("foreign capsule was pruned")
	}
}

func TestCapsuleCarriesEveryRequiredMember(t *testing.T) {
	s := testService(t, nil)
	priv := pinFresh(t, s)
	raw, _, err := s.Export()
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if _, _, err := capsule.Open(raw, priv, out); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"data/kydns.db", "data/backup_key", "config/kydns.yaml", "data/recovery.pub"} {
		if _, err := os.Stat(filepath.Join(out, p)); err != nil {
			t.Errorf("missing %s", p)
		}
	}
}

func TestScheduleIsBoundedInSeconds(t *testing.T) {
	s := testService(t, nil)
	for _, sec := range []int64{-1, 1, 14 * 60, 366*24*3600 + 1, 1 << 55} {
		if _, err := s.SetSchedule(sec); err == nil {
			t.Errorf("SetSchedule(%d) accepted", sec)
		}
	}
	got, err := s.SetSchedule(0)
	if err != nil || got != 0 {
		t.Fatalf("SetSchedule(0) = %v, %v", got, err)
	}
	got, err = s.SetSchedule(3600)
	if err != nil || got != time.Hour {
		t.Fatalf("SetSchedule(3600) = %v, %v", got, err)
	}
}

func TestUnpairKeepsThePin(t *testing.T) {
	s := testService(t, nil)
	pinFresh(t, s)
	if err := s.Unpair(); !errors.Is(err, recoveryclient.ErrNotPaired) {
		t.Fatalf("Unpair when never paired = %v", err)
	}
	// Plant a pairing record directly, as StorePairing would.
	if err := recoveryclient.StorePairing(s.Settings(), s.Sealer(), "https://recovery.example", "tok"); err != nil {
		t.Fatal(err)
	}
	if err := s.Unpair(); err != nil {
		t.Fatal(err)
	}
	st, err := s.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Paired || !st.KeyPinned {
		t.Fatalf("after unpair: %+v", st)
	}
}

func TestTokenNeverStoredInTheClear(t *testing.T) {
	s := testService(t, nil)
	pinFresh(t, s)
	if err := recoveryclient.StorePairing(s.Settings(), s.Sealer(), "https://recovery.example", "plain-secret-token"); err != nil {
		t.Fatal(err)
	}
	rows := dumpLocalSettings(t, s)
	if !strings.Contains(rows, "kyrecovery_key_id=") {
		t.Fatalf("dump read no settings, so it proves nothing: %q", rows)
	}
	if strings.Contains(rows, "plain-secret-token") {
		t.Fatal("token stored in plaintext")
	}
}

// A pin row whose recovery.pub has gone missing is a stopped backup on an instance the
// operator believes is covered, so Status must say so rather than read as unconfigured.
func TestStatusReportsAMissingKeyFile(t *testing.T) {
	s := testService(t, nil)
	pinFresh(t, s)
	if err := os.Remove(recoveryclient.RecoveryKeyPath(s.Cfg.DataDir)); err != nil {
		t.Fatal(err)
	}
	st, err := s.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.KeyPinMissing || !st.KeyPinned {
		t.Fatalf("status with no recovery.pub = %+v", st)
	}
}

func TestDrillRunsKyDNSChecks(t *testing.T) {
	s := testService(t, nil)
	res, err := s.Drill(context.Background())
	if err != nil || res == nil || !res.Passed {
		t.Fatalf("Drill = %+v, %v", res, err)
	}
	names := checkByName(t, res.Checks)
	for _, want := range []string{"sqlite integrity", "required files"} {
		if !names[want] {
			t.Errorf("check %q missing or failed", want)
		}
	}
}

// An extracted database that is empty must not pass: store.Open would have written the
// schema into it and reported the artifact it just filled as intact.
func TestDrillChecksFailOnAnEmptyDatabase(t *testing.T) {
	s := testService(t, nil)
	p, err := s.Collect()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, f := range p.Files {
		path := filepath.Join(dir, f.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, f.Data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if got := checkByName(t, drillChecks(p)(dir)); !got["required files"] || !got["sqlite integrity"] {
		t.Fatalf("intact extraction failed its own checks: %v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "kydns.db"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	got := checkByName(t, drillChecks(p)(dir))
	if got["sqlite integrity"] {
		t.Fatal("sqlite integrity passed on an empty database")
	}
	if !got["required files"] {
		t.Fatal("required files failed for the wrong reason")
	}
}

func checkByName(t *testing.T, checks []recoveryclient.Check) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, c := range checks {
		names[c.Name] = c.Passed
	}
	return names
}
