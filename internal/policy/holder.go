package policy

import (
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Busness-app/kydns-server/internal/store"
)

// Source pulls the current policy inputs. It returns an error rather than
// partial data, so a transient store failure cannot silently empty the policy.
type Source func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error)

// Holder owns the live policy snapshot. Readers on the DNS hot path call
// Decide with no lock on the snapshot itself; writers call Rebuild, which
// builds fully before swapping the pointer.
type Holder struct {
	src Source
	cur atomic.Pointer[Snapshot]

	// rebuildMu serializes Rebuild so a slower concurrent rebuild can never
	// publish a stale snapshot after a faster, later one. It is never taken on
	// the Decide/Current hot path.
	rebuildMu sync.Mutex

	blocked atomic.Uint64
	mu      sync.Mutex
	byList  map[string]uint64
	byName  map[string]uint64
}

func NewHolder(src Source) *Holder {
	return &Holder{src: src, byList: map[string]uint64{}, byName: map[string]uint64{}}
}

// maxTrackedNames caps the per-name breakdown. A random-subdomain flood arrives
// entirely on the blocked path, so an uncapped map would be a memory hole an
// outsider could dig from off-network.
const maxTrackedNames = 2000

// Rebuild pulls fresh inputs, builds a complete snapshot, and swaps it in. It
// is all-or-nothing: any error returns before the swap.
func (h *Holder) Rebuild() error {
	h.rebuildMu.Lock()
	defer h.rebuildMu.Unlock()
	set, lists, rules, err := h.src()
	if err != nil {
		return err
	}
	h.cur.Store(Build(set, lists, rules))
	return nil
}

// Current returns the live snapshot, or nil before the first successful build.
func (h *Holder) Current() *Snapshot { return h.cur.Load() }

// Decide implements dnsserver.PolicyDecider and records the block counters.
// Counting only ever happens on a block, so the common forwarded path takes no
// lock at all.
func (h *Holder) Decide(name string) (bool, string, uint32) {
	d := h.cur.Load().Decide(name)
	if d.Blocked {
		h.blocked.Add(1)
		h.mu.Lock()
		h.byList[d.Policy]++
		if _, known := h.byName[d.Name]; known || len(h.byName) < maxTrackedNames {
			h.byName[d.Name]++
		}
		h.mu.Unlock()
	}
	return d.Blocked, d.Policy, d.TTL
}

// NameCount is one entry of the blocked-name breakdown.
type NameCount struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

// TopBlocked returns the n most-blocked names, highest first. It reports what
// this network asked for, never who asked: there is no client identity in the
// counters to report.
func (h *Holder) TopBlocked(n int) []NameCount {
	h.mu.Lock()
	out := make([]NameCount, 0, len(h.byName))
	for name, count := range h.byName {
		out = append(out, NameCount{Name: name, Count: count})
	}
	h.mu.Unlock()

	slices.SortFunc(out, func(a, b NameCount) int {
		if a.Count != b.Count {
			return int(b.Count) - int(a.Count)
		}
		return strings.Compare(a.Name, b.Name) // stable order for equal counts
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// trackedNames is the cap's test seam.
func (h *Holder) trackedNames() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.byName)
}

// Counters returns blocked totals and counts by list. Client identity is never
// part of this: the counters say what was blocked, never who asked.
func (h *Holder) Counters() (uint64, map[string]uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]uint64, len(h.byList))
	for k, v := range h.byList {
		out[k] = v
	}
	return h.blocked.Load(), out
}
