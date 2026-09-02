package policy

import (
	"testing"

	"github.com/Busness-app/kydns-server/internal/store"
)

// ReplacePolicy must not trust an imported document's own builtin flag: only
// the shipped manifest, by name, may mint an undeletable, immutable list.
func TestReplacePolicyIgnoresImportedBuiltinFlag(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	_, svc := newService(t, srv)
	err := svc.ReplacePolicy(store.BlacklistSettings{Enabled: true, BlockTTL: 60},
		[]store.BlacklistList{{
			Name: "evil", URL: "https://lists.example/x", Format: FormatDomains,
			Enabled: true, IntervalSeconds: 3600, Builtin: true,
		}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	lists, err := svc.Lists()
	if err != nil {
		t.Fatal(err)
	}
	var evil *store.BlacklistList
	for i, l := range lists {
		if l.Name == "evil" {
			evil = &lists[i]
		}
	}
	if evil == nil {
		t.Fatal("imported list is missing")
	}
	if evil.Builtin {
		t.Fatal("imported list claims builtin:true and was trusted")
	}
	if err := svc.DeleteList(evil.ID); err != nil {
		t.Errorf("DeleteList() on the imported list = %v, want it deletable", err)
	}
}

// A replace-import made from a backup taken before built-ins existed must not
// leave filtering with no shipped list until the next restart.
func TestReplacePolicyReseedsBuiltins(t *testing.T) {
	srv := quietServer(t, "ads.example\n")
	_, svc := newService(t, srv)
	if err := svc.ReplacePolicy(store.BlacklistSettings{Enabled: true, BlockTTL: 60}, nil, nil); err != nil {
		t.Fatal(err)
	}
	lists, err := svc.Lists()
	if err != nil {
		t.Fatal(err)
	}
	m, err := BuiltinManifest()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range m.Lists {
		found := false
		for _, l := range lists {
			if l.Name == b.Name && l.Builtin {
				found = true
			}
		}
		if !found {
			t.Errorf("lists = %+v, want the shipped built-in %q reseeded", lists, b.Name)
		}
	}
}
