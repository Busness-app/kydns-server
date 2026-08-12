package policy

import (
	"errors"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

func testHolder(t *testing.T, src Source) *Holder {
	t.Helper()
	h := NewHolder(src)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHolderDecidesAndCounts(t *testing.T) {
	h := testHolder(t, func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		return store.BlacklistSettings{Enabled: true, BlockTTL: 60},
			[]store.BlacklistList{{Name: "l1", Enabled: true, Snapshot: []string{"ads.example"}}},
			nil, nil
	})
	for i := 0; i < 3; i++ {
		blocked, decision, ttl := h.Decide("ads.example.")
		if !blocked || decision != "l1" || ttl != 60 {
			t.Fatalf("Decide() = %v %q %d, want blocked by l1 at 60", blocked, decision, ttl)
		}
	}
	if blocked, _, _ := h.Decide("example.org"); blocked {
		t.Error("Decide(example.org) blocked")
	}
	total, byList := h.Counters()
	if total != 3 || byList["l1"] != 3 {
		t.Errorf("Counters() = %d %v, want 3 blocks all from l1", total, byList)
	}
}

// A failed rebuild keeps the previous snapshot serving, exactly like the zone
// holder: a transient store error must not silently disable filtering.
func TestFailedRebuildKeepsThePreviousSnapshot(t *testing.T) {
	fail := false
	h := testHolder(t, func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		if fail {
			return store.BlacklistSettings{}, nil, nil, errors.New("store is down")
		}
		return store.BlacklistSettings{Enabled: true, BlockTTL: 60},
			[]store.BlacklistList{{Name: "l1", Enabled: true, Snapshot: []string{"ads.example"}}},
			nil, nil
	})
	fail = true
	if err := h.Rebuild(); err == nil {
		t.Fatal("Rebuild() succeeded, want the store error surfaced")
	}
	if blocked, _, _ := h.Decide("ads.example"); !blocked {
		t.Error("after a failed rebuild the name is no longer blocked")
	}
}

func TestHolderBeforeFirstBuildBlocksNothing(t *testing.T) {
	h := NewHolder(func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		return store.BlacklistSettings{}, nil, nil, nil
	})
	if blocked, decision, _ := h.Decide("ads.example"); blocked || decision != PolicyForwarded {
		t.Errorf("Decide() before the first build = %v %q, want forwarded", blocked, decision)
	}
}
