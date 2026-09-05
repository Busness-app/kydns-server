package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kydns-server/internal/config"
	"github.com/Busness-app/kydns-server/internal/store"
)

func openedDrill(t *testing.T, p recoveryclient.Payload) (string, capsule.Manifest) {
	t.Helper()
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := recoveryclient.Seal(p, recoveryclient.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	m, _, err := capsule.Open(raw, priv, dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, m
}

func TestDrillRejectsMalformedRecipes(t *testing.T) {
	s := testService(t, nil)
	p, err := s.Collect()
	if err != nil {
		t.Fatal(err)
	}
	dir, opened := openedDrill(t, p)
	for name, mutate := range map[string]func(*capsule.Manifest, map[string]any){
		"nil":              func(m *capsule.Manifest, _ map[string]any) { m.VerificationRecipe = nil },
		"wrong object":     func(m *capsule.Manifest, _ map[string]any) { m.VerificationRecipe = "recipe" },
		"foreign service":  func(m *capsule.Manifest, _ map[string]any) { m.ServiceName = "KySignOn" },
		"missing flag":     func(_ *capsule.Manifest, r map[string]any) { delete(r, "check_sqlite_integrity") },
		"false flag":       func(_ *capsule.Manifest, r map[string]any) { r["check_sqlite_integrity"] = false },
		"wrong flag":       func(_ *capsule.Manifest, r map[string]any) { r["check_sqlite_integrity"] = []any{true} },
		"missing required": func(_ *capsule.Manifest, r map[string]any) { delete(r, "required_files") },
		"empty required":   func(_ *capsule.Manifest, r map[string]any) { r["required_files"] = []any{} },
		"wrong list":       func(_ *capsule.Manifest, r map[string]any) { r["required_files"] = "data/kydns.db" },
		"mixed list":       func(_ *capsule.Manifest, r map[string]any) { r["required_files"] = []any{"data/kydns.db", 7} },
		"missing backup key": func(_ *capsule.Manifest, r map[string]any) {
			r["required_files"] = []any{"data/kydns.db", "config/kydns.yaml"}
		},
		"missing sqlite": func(_ *capsule.Manifest, r map[string]any) { delete(r, "sqlite_paths") },
		"empty sqlite":   func(_ *capsule.Manifest, r map[string]any) { r["sqlite_paths"] = []any{} },
		"wrong sqlite":   func(_ *capsule.Manifest, r map[string]any) { r["sqlite_paths"] = []any{"data/backup_key"} },
		"duplicate": func(_ *capsule.Manifest, r map[string]any) {
			r["required_files"] = append(r["required_files"].([]any), "data/kydns.db")
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := opened
			raw, _ := json.Marshal(opened.VerificationRecipe)
			var r map[string]any
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			m.VerificationRecipe = r
			mutate(&m, r)
			got := drillChecks(dir, m)
			if len(got) != 1 || got[0].Name != "verification recipe" || got[0].Passed {
				t.Fatalf("must fail before reading members: %+v", got)
			}
		})
	}
	for _, path := range []string{"", ".", "../outside", "/outside", "data/../outside", "data//kydns.db", "data/./kydns.db", `data\kydns.db`, "C:/outside", "data/unlisted", "data/\x00"} {
		t.Run("path "+path, func(t *testing.T) {
			m := opened
			m.VerificationRecipe = map[string]any{"check_sqlite_integrity": true, "required_files": []any{path}, "sqlite_paths": []any{"data/kydns.db"}}
			if got := drillChecks(dir, m); len(got) != 1 || got[0].Passed {
				t.Fatalf("accepted path: %+v", got)
			}
		})
	}
}

func TestDrillChecksRestoredContents(t *testing.T) {
	s := testService(t, nil)
	pinFresh(t, s)
	if err := recoveryclient.StorePairing(s.Settings(), s.Sealer(), "https://recovery.example", "synthetic-drill-token"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Cfg.DataDir, "node_key"), bytes.Repeat([]byte{1}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := s.Collect()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, member, contents, check string }{
		{"empty db", "data/kydns.db", "", "sqlite integrity"},
		{"corrupt db", "data/kydns.db", "corrupt", "sqlite integrity"},
		{"short key", "data/backup_key", "short", "backup key"},
		{"wrong key", "data/backup_key", strings.Repeat("ab", 32), "recovery pairing"},
		{"yaml syntax", "config/kydns.yaml", "dns: [", "configuration"},
		{"yaml missing data", "config/kydns.yaml", "dns:\n  listen: :53\n", "configuration"},
		{"yaml listener", "config/kydns.yaml", "data_dir: /tmp\ndns:\n  listen: invalid\nadmin:\n  listen: :8053\n", "configuration"},
		{"identity", "data/node_key", "short", "node identity"},
		{"public key", "data/recovery.pub", "invalid", "recovery pairing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, m := openedDrill(t, p)
			for _, c := range drillChecks(dir, m) {
				if !c.Passed {
					t.Fatalf("valid fixture failed: %+v", c)
				}
			}
			file := filepath.Join(dir, tc.member)
			if err := os.WriteFile(file, []byte(tc.contents), 0600); err != nil {
				t.Fatal(err)
			}
			got := checkByName(t, drillChecks(dir, m))
			if pass, ok := got[tc.check]; !ok || pass {
				t.Fatalf("%s did not fail: %+v", tc.check, got)
			}
			after, err := os.ReadFile(file)
			if err != nil || !bytes.Equal(after, []byte(tc.contents)) {
				t.Fatal("check changed the artifact")
			}
		})
	}
	for _, member := range []string{"data/kydns.db", "data/backup_key", "config/kydns.yaml", "data/node_key", "data/recovery.pub"} {
		t.Run("missing "+member, func(t *testing.T) {
			dir, m := openedDrill(t, p)
			if err := os.Remove(filepath.Join(dir, member)); err != nil {
				t.Fatal(err)
			}
			if got := checkByName(t, drillChecks(dir, m)); got["required files"] {
				t.Fatal("missing member passed")
			}
		})
	}
	for _, member := range []string{"data/node_key", "data/recovery.pub"} {
		t.Run("recipe omits "+member, func(t *testing.T) {
			dir, m := openedDrill(t, p)
			r := m.VerificationRecipe.(map[string]any)
			var required []any
			for _, v := range r["required_files"].([]any) {
				if v != member {
					required = append(required, v)
				}
			}
			r["required_files"] = required
			if got := drillChecks(dir, m); len(got) != 1 || got[0].Passed {
				t.Fatalf("omission passed: %+v", got)
			}
		})
	}
	for _, kind := range []string{"directory", "symlink", "parent symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir, m := openedDrill(t, p)
			file := filepath.Join(dir, "data/backup_key")
			if kind == "parent symlink" {
				if err := os.Rename(filepath.Join(dir, "data"), filepath.Join(dir, "real-data")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(dir, "real-data"), filepath.Join(dir, "data")); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if kind == "directory" {
					err = os.Mkdir(file, 0700)
				} else {
					err = os.Symlink(filepath.Join(s.Cfg.DataDir, "backup_key"), file)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if got := checkByName(t, drillChecks(dir, m)); got["required files"] {
				t.Fatal("nonregular path passed")
			}
		})
	}
}

func TestPairingFromV050SurvivesUpgrade(t *testing.T) {
	var f struct {
		Version              string
		Key, KeyFile, Public []byte
		Token                string
		Settings             map[string]string
	}
	raw, err := os.ReadFile("testdata/pairing-v050.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != "v0.5.0" {
		t.Fatal("fixture must come from v0.5.0")
	}
	dir := t.TempDir()
	for name, b := range map[string][]byte{"backup_key": f.KeyFile, "recovery.pub": f.Public} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.Open(filepath.Join(dir, "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for k, v := range f.Settings {
		if err := st.SetLocalSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		s, err := New(&config.Config{DataDir: dir, DNS: config.DNSConfig{Listen: ":53"}, Admin: config.AdminConfig{Listen: ":8053"}}, st, "test")
		if err != nil {
			t.Fatal(err)
		}
		p, err := recoveryclient.LoadPairing(dir, s.Settings(), s.Sealer())
		if err != nil {
			t.Fatal(err)
		}
		if p.Token != f.Token || p.URL != f.Settings["kyrecovery_url"] || p.Key.Public.ID() != f.Settings["kyrecovery_key_id"] || p.Key.Threshold != 2 || p.Key.TotalShares != 3 {
			t.Fatal("pairing changed")
		}
		for k, want := range f.Settings {
			got, err := st.GetLocalSetting(k)
			if err != nil || got != want {
				t.Fatalf("setting %s changed", k)
			}
		}
		for name, want := range map[string][]byte{"backup_key": f.KeyFile, "recovery.pub": f.Public} {
			got, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("%s changed", name)
			}
		}
		r, err := s.Drill(context.Background())
		if err != nil || !r.Passed {
			t.Fatalf("old pairing drill failed: %+v, %v", r, err)
		}
	}
}

func TestDrillRejectsBrokenRestoredPairings(t *testing.T) {
	s := testService(t, nil)
	pinFresh(t, s)
	if err := recoveryclient.StorePairing(s.Settings(), s.Sealer(), "https://recovery.example", "synthetic-token"); err != nil {
		t.Fatal(err)
	}
	p, err := s.Collect()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, key, value string
		remove           bool
	}{
		{"corrupt token", "kyrecovery_token_enc", "do-not-print-this-ciphertext", false},
		{"empty token", "kyrecovery_token_enc", "", false},
		{"lost token", "kyrecovery_token_enc", "", true},
		{"lost URL", "kyrecovery_url", "", true},
		{"lost pin", "kyrecovery_key_id", "", true},
		{"wrong pin", "kyrecovery_key_id", "other", false},
		{"invalid threshold", "kyrecovery_threshold", "1", false},
		{"invalid total", "kyrecovery_total_shares", "0", false},
		{"missing topology", "kyrecovery_threshold", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, m := openedDrill(t, p)
			st, err := store.Open(filepath.Join(dir, "data/kydns.db"))
			if err != nil {
				t.Fatal(err)
			}
			if tc.remove {
				err = st.DeleteLocalSetting(tc.key)
			} else {
				err = st.SetLocalSetting(tc.key, tc.value)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			checks := drillChecks(dir, m)
			if pass, ok := checkByName(t, checks)["recovery pairing"]; !ok || pass {
				t.Fatalf("broken pairing passed: %+v", checks)
			}
			for _, c := range checks {
				if strings.Contains(c.Message, "do-not-print-this-ciphertext") || strings.Contains(c.Message, "synthetic-token") {
					t.Fatal("check leaked credentials")
				}
			}
		})
	}
}

func TestDrillSandboxPermissionsAndFailureCleanup(t *testing.T) {
	s := testService(t, nil)
	p, err := s.Collect()
	if err != nil {
		t.Fatal(err)
	}
	var scratch string
	result, err := recoveryclient.Drill(context.Background(), s.Cfg.DataDir, p, func(dir string, opened capsule.Manifest) []recoveryclient.Check {
		scratch = dir
		if filepath.Dir(dir) != s.Cfg.DataDir {
			t.Fatal("sandbox outside data directory")
		}
		info, err := os.Stat(dir)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("sandbox is not owner-only")
		}
		for _, f := range opened.Files {
			info, err := os.Stat(filepath.Join(dir, f.Path))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("member is not owner-only")
			}
		}
		if err := os.Remove(filepath.Join(dir, "data/backup_key")); err != nil {
			t.Fatal(err)
		}
		return drillChecks(dir, opened)
	})
	if err != nil || result.Passed || scratch == "" {
		t.Fatalf("failed drill = %+v, %v", result, err)
	}
	if _, err := os.Stat(scratch); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed drill left scratch")
	}
}

// Inspect the guard from inside the first operation under it, without a sleep
// or a production test hook. A missing or early-unlocked mutex fails TryLock.
type drillContext struct {
	context.Context
	inspect func()
}

func (c drillContext) Err() error { c.inspect(); return c.Context.Err() }

func TestDrillSerializationAndCancellation(t *testing.T) {
	s := testService(t, nil)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			ctx := drillContext{context.Background(), func() {
				if s.drillMu.TryLock() {
					s.drillMu.Unlock()
					t.Error("drill guard was not held")
				}
			}}
			r, err := s.Drill(ctx)
			if err != nil || !r.Passed {
				t.Errorf("Drill = %+v, %v", r, err)
			}
		})
	}
	wg.Wait()
	before, err := os.ReadDir(s.Cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Holding the mutex makes this a waiting cancellation; release then await.
	s.drillMu.Lock()
	done := make(chan error, 1)
	go func() { _, err := s.Drill(ctx); done <- err }()
	s.drillMu.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled drill = %v", err)
	}
	after, err := os.ReadDir(s.Cfg.DataDir)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("canceled drill changed the data directory")
	}
	for _, e := range after {
		if strings.HasPrefix(e.Name(), "recoveryclient-drill-") || strings.HasPrefix(e.Name(), ".backup-") {
			t.Fatal("drill left scratch behind")
		}
	}
}
