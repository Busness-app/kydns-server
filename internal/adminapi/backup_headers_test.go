package adminapi

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kydns-server/internal/backup"
	"github.com/Busness-app/kydns-server/internal/config"
	"github.com/Busness-app/kydns-server/internal/store"
)

func TestBackupExportDisablesCachingAndSniffing(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	private, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.StoreRecoveryKey(st, dir, backup.RecoveryKey{Public: private.Public(), Threshold: 2, TotalShares: 3}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DataDir: dir, DNS: config.DNSConfig{Listen: ":53"}, Admin: config.AdminConfig{Listen: "127.0.0.1:8053"}}
	a := &API{backup: &BackupService{Config: cfg, Store: st, Version: "test"}}
	rec := httptest.NewRecorder()
	a.backupExport(rec, httptest.NewRequest("GET", "/api/v1/backup/export-capsule", nil))
	if rec.Code != 200 {
		t.Fatalf("export = %d: %s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}
