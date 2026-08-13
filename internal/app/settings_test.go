package app

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/config"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func testConfig(t *testing.T, body string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kydns.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestEnsureSettingsSeedsOnce(t *testing.T) {
	st := testStore(t)
	cfg := testConfig(t, "data_dir: "+t.TempDir()+"\ndns:\n  private_domain: first.example\n")

	boot, err := ensureSettings(st, cfg, slog.Default())
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if boot.PrivateDomain != "first.example" {
		t.Fatalf("the file did not seed the database: %+v", boot)
	}

	// An operator edits the value in the UI.
	stored, _, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	stored.PrivateDomain = "edited.example"
	if err := st.PutSettings(stored); err != nil {
		t.Fatal(err)
	}

	// A second start with a different file must not overwrite it. This is the
	// whole precedence rule: the database wins, the file seeds once.
	cfg2 := testConfig(t, "data_dir: "+t.TempDir()+"\ndns:\n  private_domain: second.example\n")
	boot, err = ensureSettings(st, cfg2, slog.Default())
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if boot.PrivateDomain != "edited.example" {
		t.Errorf("the config file overwrote a stored setting: %q", boot.PrivateDomain)
	}
}

// A config file that would seed an invalid database must fail at startup
// rather than store something the UI can never save again.
func TestEnsureSettingsRejectsAnInvalidSeed(t *testing.T) {
	st := testStore(t)
	cfg := testConfig(t, "data_dir: "+t.TempDir()+"\ndns:\n  allow_query: [\"0.0.0.0/0\"]\n")
	if _, err := ensureSettings(st, cfg, slog.Default()); err == nil {
		t.Fatal("an open-resolver ACL was seeded from the file with no complaint")
	}
}

// A database edited by hand, or written by an older version, must not start a
// half-configured server.
func TestEnsureSettingsRejectsInvalidStoredSettings(t *testing.T) {
	st := testStore(t)
	cfg := testConfig(t, "data_dir: "+t.TempDir()+"\n")
	boot, err := ensureSettings(st, cfg, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	boot.AllowQuery = nil // default-closed: refuses every query
	if err := st.PutSettings(boot); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureSettings(st, cfg, slog.Default()); err == nil {
		t.Fatal("a stored settings row with an empty ACL started the server")
	}
}

func TestRestartPending(t *testing.T) {
	boot := store.Settings{PrivateDomain: "home.arpa", DHCPLeaseFile: ""}

	if got := restartPending(boot, boot); len(got) != 0 {
		t.Errorf("unchanged settings report a pending restart: %+v", got)
	}

	cur := boot
	cur.PrivateDomain = "lab.example"
	cur.DHCPLeaseFile = "/var/lib/misc/dnsmasq.leases"
	got := restartPending(boot, cur)
	if len(got) != 2 {
		t.Fatalf("got %d pending items, want 2: %+v", len(got), got)
	}
	// The banner has to name both values, or the operator cannot tell which
	// one is actually serving queries right now.
	for _, it := range got {
		if it.Running == "" || it.Stored == "" || it.Key == "" {
			t.Errorf("incomplete item: %+v", it)
		}
	}

	// Only these two keys are restart-required. Everything else applies live,
	// so a live-applied change must never raise the banner.
	live := boot
	live.TTL = 999
	live.LogQueries = true
	if got := restartPending(boot, live); len(got) != 0 {
		t.Errorf("a live-applied change raised the restart banner: %+v", got)
	}
}
