package policy

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// Source pulls the current policy inputs. It returns an error rather than
// partial data, so a transient store failure cannot silently empty the policy.
type Source func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error)

// Holder owns the live policy snapshot. Readers on the DNS hot path call
// Decide with no lock on the snapshot itself; writers call Rebuild, which
// builds fully before swapping the pointer.
type Holder struct {
	src    Source
	logger *slog.Logger
	cur    atomic.Pointer[Snapshot]

	blocked atomic.Uint64
	mu      sync.Mutex
	byList  map[string]uint64
}

func NewHolder(src Source, logger *slog.Logger) *Holder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Holder{src: src, logger: logger, byList: map[string]uint64{}}
}

// Rebuild pulls fresh inputs, builds a complete snapshot, and swaps it in. It
// is all-or-nothing: any error returns before the swap.
func (h *Holder) Rebuild() error {
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
		h.mu.Unlock()
	}
	return d.Blocked, d.Policy, d.TTL
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
