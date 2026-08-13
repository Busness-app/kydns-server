package policy

import (
	"strconv"
	"testing"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// blockEverything denies the "example" apex, which Set.Match extends to every
// subdomain, so a test can drive as many distinct blocked names through Decide
// as it likes.
func blockEverything(t *testing.T) *Holder {
	t.Helper()
	return testHolder(t, func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		return store.BlacklistSettings{Enabled: true, BlockTTL: 60},
			nil,
			[]store.BlacklistRule{{Kind: PolicyDeny, Domain: "example"}}, nil
	})
}

func TestTopBlockedRanksByCount(t *testing.T) {
	h := blockEverything(t)
	for i := 0; i < 5; i++ {
		h.Decide("ads.example")
	}
	for i := 0; i < 2; i++ {
		h.Decide("track.example")
	}
	h.Decide("once.example")

	top := h.TopBlocked(2)
	if len(top) != 2 {
		t.Fatalf("TopBlocked(2) returned %d entries, want 2", len(top))
	}
	if top[0].Name != "ads.example" || top[0].Count != 5 {
		t.Errorf("top[0] = %+v, want ads.example at 5", top[0])
	}
	if top[1].Name != "track.example" || top[1].Count != 2 {
		t.Errorf("top[1] = %+v, want track.example at 2", top[1])
	}
}

// A random-subdomain flood is a real attack shape, and it lands entirely on the
// blocked path. The name map must stop growing rather than track every label an
// attacker cares to invent.
func TestTopBlockedNameMapIsBounded(t *testing.T) {
	h := blockEverything(t)
	for i := 0; i < maxTrackedNames+500; i++ {
		h.Decide("flood" + strconv.Itoa(i) + ".example")
	}

	if n := h.trackedNames(); n > maxTrackedNames {
		t.Errorf("tracked %d names, want at most %d", n, maxTrackedNames)
	}
	// Blocking still counts in full — only the per-name breakdown is capped.
	if total, _ := h.Counters(); total != uint64(maxTrackedNames+500) {
		t.Errorf("blocked total = %d, want %d", total, maxTrackedNames+500)
	}
}

// Once the map is full, a name already in it must keep counting, or the chart
// freezes the moment a flood fills the table.
func TestTopBlockedKeepsCountingKnownNamesWhenFull(t *testing.T) {
	h := blockEverything(t)
	h.Decide("ads.example")
	for i := 0; i < maxTrackedNames+10; i++ {
		h.Decide("flood" + strconv.Itoa(i) + ".example")
	}
	h.Decide("ads.example")

	for _, e := range h.TopBlocked(maxTrackedNames) {
		if e.Name == "ads.example" {
			if e.Count != 2 {
				t.Errorf("ads.example counted %d times, want 2", e.Count)
			}
			return
		}
	}
	t.Error("ads.example fell out of the tracked names")
}

func TestTopBlockedEmptyBeforeAnyBlock(t *testing.T) {
	h := blockEverything(t)
	if top := h.TopBlocked(5); len(top) != 0 {
		t.Errorf("TopBlocked() = %v before any block, want empty", top)
	}
}
