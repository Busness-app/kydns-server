package policy

import (
	"strings"
	"testing"

	"github.com/Busness-app/kydns-server/internal/store"
	"path/filepath"
)

func TestBuiltinManifestIsUsable(t *testing.T) {
	m, err := BuiltinManifest()
	if err != nil {
		t.Fatal(err)
	}
	if m.Version < 1 || len(m.Lists) == 0 {
		t.Fatalf("manifest = %+v, want a versioned, non-empty manifest", m)
	}
	for _, l := range m.Lists {
		if l.Name == "" || l.License == "" || l.Attribution == "" || l.Description == "" {
			t.Errorf("built-in %+v is missing name, description, license or attribution", l)
		}
		if !strings.HasPrefix(l.URL, "https://") {
			t.Errorf("built-in %s uses %q, want an https URL", l.Name, l.URL)
		}
		if !ValidFormat(l.Format) {
			t.Errorf("built-in %s declares format %q", l.Name, l.Format)
		}
		if l.IntervalSeconds <= 0 {
			t.Errorf("built-in %s has interval %d", l.Name, l.IntervalSeconds)
		}
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "kydns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSeedBuiltinsIsIdempotentAndRespectsOperatorEdits(t *testing.T) {
	st := openStore(t)
	if err := SeedBuiltins(st); err != nil {
		t.Fatal(err)
	}
	lists, err := st.BlacklistListMetas()
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) == 0 {
		t.Fatal("SeedBuiltins() added nothing")
	}
	// Built-ins are on by default.
	if !lists[0].Enabled || !lists[0].Builtin {
		t.Errorf("seeded list = %+v, want enabled and marked built-in", lists[0])
	}

	// An operator turns one off; re-seeding must not turn it back on.
	off := lists[0]
	off.Enabled = false
	if _, err := st.PutBlacklistList(off); err != nil {
		t.Fatal(err)
	}
	if err := SeedBuiltins(st); err != nil {
		t.Fatal(err)
	}
	after, err := st.BlacklistListMetas()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(lists) {
		t.Errorf("re-seeding produced %d lists, want %d", len(after), len(lists))
	}
	if after[0].Enabled {
		t.Error("re-seeding re-enabled a list the operator turned off")
	}
}
