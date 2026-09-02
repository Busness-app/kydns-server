package policy

import (
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busness-app/kydns-server/internal/store"
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

// Rebuild must be serialized end to end (read and store together), or a slow
// rebuild that read stale data can publish after a fast one that read fresh
// data, silently reverting a just-added rule. This reproduces the exact
// interleaving finding 4 describes: a slow reader starts first, a fast writer
// finishes first, and the slow reader must not then overwrite it.
func TestConcurrentRebuildsDoNotLoseTheLatestSourceState(t *testing.T) {
	var gen atomic.Int64
	var slowDone atomic.Bool
	h := testHolder(t, func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		n := gen.Load()
		if n == 0 && !slowDone.Load() {
			// The first (slow) rebuild reads gen=0, then stalls, simulating a
			// build that takes longer than the next admin mutation.
			time.Sleep(50 * time.Millisecond)
			slowDone.Store(true)
		}
		name := "l" + strconv.FormatInt(n, 10)
		return store.BlacklistSettings{Enabled: true, BlockTTL: 60},
			[]store.BlacklistList{{Name: name, Enabled: true, Snapshot: []string{"ads.example"}}},
			nil, nil
	})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := h.Rebuild(); err != nil {
			t.Error(err)
		}
	}()
	// Give the slow rebuild time to enter Rebuild before the fast one races it.
	time.Sleep(10 * time.Millisecond)
	gen.Store(1)
	if err := h.Rebuild(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	if _, decision, _ := h.Decide("ads.example"); decision != "l1" {
		t.Errorf("Decide() after a concurrent rebuild = %q, want the latest source state %q", decision, "l1")
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
