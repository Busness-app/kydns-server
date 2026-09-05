package app

import (
	"context"
	"database/sql"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kydns-server/internal/backup"
	"github.com/Busness-app/kydns-server/internal/config"
	"github.com/Busness-app/kydns-server/internal/store"
	_ "modernc.org/sqlite"
)

func TestBackupLoopReportsAPinnedKeyWithNoKeyFile(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := &config.Config{
		DataDir:               dir,
		BackupDir:             filepath.Join(dir, "backups"),
		BackupKeep:            7,
		BackupDepositInterval: 15 * time.Minute,
	}
	svc, err := backup.New(cfg, st, "test")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(priv.Public().Bytes())
	if _, err := svc.PinKey(key, 2, 3); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(recoveryclient.RecoveryKeyPath(dir)); err != nil {
		t.Fatal(err)
	}

	backupLoopOnce(context.Background(), svc, slog.New(slog.DiscardHandler))

	db, err := sql.Open("sqlite", filepath.Join(dir, "kydns.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action='admin.backup_run' AND outcome='failure'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("failure audit rows = %d, want 1", n)
	}
}
