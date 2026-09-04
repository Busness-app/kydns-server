package backup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kydns-server/internal/config"
	"github.com/Busness-app/kydns-server/internal/store"
)

func testStore(t *testing.T) (*store.Store, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st, &config.Config{DataDir: dir, DNS: config.DNSConfig{Listen: ":53"}, Admin: config.AdminConfig{Listen: "127.0.0.1:8053"}}
}

func TestPairingTokenIsSealedAndCapsuleOpensOnlyWithPrivateKey(t *testing.T) {
	st, cfg := testStore(t)
	private, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	key := RecoveryKey{Public: private.Public(), Threshold: 2, TotalShares: 3}
	if err := StorePairing(st, cfg.DataDir, "https://recovery.example", "plain-secret-token", key); err != nil {
		t.Fatal(err)
	}
	stored, err := st.GetLocalSetting(settingToken)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "plain-secret-token") {
		t.Fatal("pairing token stored in plaintext")
	}
	pairing, err := LoadPairing(st, cfg.DataDir)
	if err != nil || pairing.Token != "plain-secret-token" {
		t.Fatalf("LoadPairing = %+v, %v", pairing, err)
	}
	raw, _, err := Seal(cfg, st, "test", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := capsule.Open(raw, private, ""); err != nil {
		t.Fatal(err)
	}
	wrong, _ := recoverykey.Generate()
	if _, _, err := capsule.Open(raw, wrong, ""); !errors.Is(err, capsule.ErrWrongRecoveryKey) {
		t.Fatalf("wrong key error = %v", err)
	}
}

func TestRecoveryURLValidation(t *testing.T) {
	for _, raw := range []string{"http://example.com", "https://127.0.0.1", "https://100.64.0.1", "https://example.com?q=x", "https://example.com/#x", "https://u:p@example.com"} {
		if _, err := endpoint(raw, "/api/pairing/claim"); err == nil {
			t.Errorf("endpoint(%q) accepted", raw)
		}
	}
}

func TestDrillChecksExtractedDatabase(t *testing.T) {
	st, cfg := testStore(t)
	got, err := Drill(cfg, st, "test")
	if err != nil || !got.Passed {
		t.Fatalf("Drill = %+v, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "backup_key")); err != nil {
		t.Fatal(err)
	}
}
