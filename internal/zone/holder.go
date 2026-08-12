package zone

import (
	"log/slog"
	"sync/atomic"
)

// Source pulls the current registry contents. It returns an error rather than
// partial data so a transient store failure cannot silently empty the zone.
type Source func() (Input, error)

// Holder owns the live snapshot. Readers on the DNS hot path call Current with
// no lock; writers call Rebuild, which builds fully before swapping the
// pointer. A failed build leaves the previous snapshot in place.
type Holder struct {
	src    Source
	logger *slog.Logger
	cur    atomic.Pointer[Snapshot]
	gen    atomic.Uint32
}

func NewHolder(src Source, logger *slog.Logger) *Holder { return &Holder{src: src, logger: logger} }

// Rebuild pulls fresh input, builds a complete snapshot, and swaps it in. It
// is all-or-nothing: any error returns before the swap.
func (h *Holder) Rebuild() error {
	in, err := h.src()
	if err != nil {
		return err
	}
	// Reserve the generation before building so the SOA serial always advances,
	// even across a failed attempt. Serials must never go backwards.
	in.Generation = h.gen.Add(1)
	snap, err := Build(in, h.logger)
	if err != nil {
		return err
	}
	h.cur.Store(snap)
	return nil
}

// Current returns the live snapshot, or nil before the first successful build.
func (h *Holder) Current() *Snapshot { return h.cur.Load() }

// Generation is the current SOA serial.
func (h *Holder) Generation() uint32 { return h.gen.Load() }
