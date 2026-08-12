package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/auth"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// seeded writes a config and a database with an existing admin password.
func seeded(t *testing.T, existing string) (cfgPath, dir string) {
	t.Helper()
	dir = t.TempDir()
	cfgPath = filepath.Join(dir, "kydns.yaml")
	if err := os.WriteFile(cfgPath, []byte("data_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if existing != "" {
		hash, err := auth.HashPassword(existing)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SetAdminPassword(hash); err != nil {
			t.Fatal(err)
		}
	}
	return cfgPath, dir
}

// answers returns a PasswordReader that replies with each value in turn.
func answers(vals ...string) PasswordReader {
	i := 0
	return func(string) (string, error) {
		v := vals[i]
		if i < len(vals)-1 {
			i++
		}
		return v, nil
	}
}

func adminHash(t *testing.T, dir string) string {
	t.Helper()
	st, err := store.Open(filepath.Join(dir, "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h, err := st.AdminHash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// The whole point: a forgotten password is recoverable.
func TestResetAdminPasswordReplacesIt(t *testing.T) {
	cfg, dir := seeded(t, "the-old-password")
	var out bytes.Buffer
	if err := ResetAdminPassword(cfg, answers("a-brand-new-password", "a-brand-new-password"), &out); err != nil {
		t.Fatal(err)
	}
	hash := adminHash(t, dir)
	if !auth.VerifyPassword(hash, "a-brand-new-password") {
		t.Error("the new password does not verify")
	}
	if auth.VerifyPassword(hash, "the-old-password") {
		t.Error("the old password still works")
	}
	if !strings.Contains(out.String(), "Restart KyDNS") {
		t.Error("output does not mention that sessions survive until a restart")
	}
}

// Recovery must also work when setup was never completed.
func TestResetWorksWithNoExistingAdmin(t *testing.T) {
	cfg, dir := seeded(t, "")
	if err := ResetAdminPassword(cfg, answers("a-brand-new-password", "a-brand-new-password"), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !auth.VerifyPassword(adminHash(t, dir), "a-brand-new-password") {
		t.Error("password was not set")
	}
}

func TestResetRejectsMismatch(t *testing.T) {
	cfg, dir := seeded(t, "the-old-password")
	err := ResetAdminPassword(cfg, answers("a-brand-new-password", "a-different-password"), &bytes.Buffer{})
	if err == nil {
		t.Fatal("mismatched passwords were accepted")
	}
	if !auth.VerifyPassword(adminHash(t, dir), "the-old-password") {
		t.Error("a failed reset changed the stored password")
	}
}

func TestResetRejectsShortPassword(t *testing.T) {
	cfg, dir := seeded(t, "the-old-password")
	if err := ResetAdminPassword(cfg, answers("short", "short"), &bytes.Buffer{}); err == nil {
		t.Fatal("a short password was accepted")
	}
	if !auth.VerifyPassword(adminHash(t, dir), "the-old-password") {
		t.Error("a failed reset changed the stored password")
	}
}

// A missing database is a clear message, not a confusing SQLite error or a
// silently created empty one.
func TestResetWithoutDatabaseExplains(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "kydns.yaml")
	if err := os.WriteFile(cfg, []byte("data_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ResetAdminPassword(cfg, answers("a-brand-new-password", "a-brand-new-password"), &bytes.Buffer{})
	if err == nil {
		t.Fatal("reset succeeded with no database")
	}
	if !strings.Contains(err.Error(), "no database") {
		t.Errorf("error = %v, want it to name the missing database", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "kydns.db")); statErr == nil {
		t.Error("a database was created by a failed reset")
	}
}

func TestResetRejectsBadConfigPath(t *testing.T) {
	if err := ResetAdminPassword(filepath.Join(t.TempDir(), "absent.yaml"),
		answers("a-brand-new-password"), &bytes.Buffer{}); err == nil {
		t.Error("reset succeeded with no config file")
	}
}

// After a reset the operator can sign in through the web UI with the new
// password: the recovery path actually restores access.
func TestResetRestoresWebLogin(t *testing.T) {
	cfg, dir := seeded(t, "the-old-password")
	if err := ResetAdminPassword(cfg, answers("a-brand-new-password", "a-brand-new-password"), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	hash, err := st.AdminHash()
	if err != nil {
		t.Fatal(err)
	}
	if !auth.VerifyPassword(hash, "a-brand-new-password") {
		t.Error("the stored hash does not accept the new password")
	}
}
