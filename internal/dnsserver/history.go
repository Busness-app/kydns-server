package dnsserver

import (
	"sync"
	"time"
)

// histSlots is the ring length in one-minute buckets: the dashboard graphs the
// last hour.
const histSlots = 60

// Bucket is one minute of traffic. Like RefusalStats it is counts only, so a
// bucket can be served to the dashboard whatever the query-logging opt-in says.
type Bucket struct {
	Minute        int64  `json:"minute"` // unix minute, i.e. unix seconds / 60
	Authoritative uint64 `json:"authoritative"`
	Forwarded     uint64 `json:"forwarded"`
	Blocked       uint64 `json:"blocked"`
	CacheHits     uint64 `json:"cache_hits"`
	CacheMisses   uint64 `json:"cache_misses"`
	LatencySum    uint64 `json:"latency_sum_ms"`
	LatencyCount  uint64 `json:"latency_count"`
}

// history is a fixed ring of per-minute buckets. There is no ticker: a slot
// carries the minute it belongs to, so a slot whose stamp does not match is
// stale and reads as an empty minute. That keeps the memory constant and means
// a server left idle overnight cannot wake up graphing yesterday's traffic.
type history struct {
	mu    sync.Mutex
	slots [histSlots]Bucket
	now   func() time.Time
}

func newHistory(now func() time.Time) *history {
	if now == nil {
		now = time.Now
	}
	return &history{now: now}
}

// current returns the live bucket for minute, resetting a stale slot first.
// The caller holds mu.
func (h *history) current(minute int64) *Bucket {
	b := &h.slots[minute%histSlots]
	if b.Minute != minute {
		*b = Bucket{Minute: minute}
	}
	return b
}

func (h *history) add(o outcome, d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b := h.current(h.now().Unix() / 60)
	switch o {
	case outcomeAuthoritative:
		b.Authoritative++
	case outcomeForwarded:
		b.Forwarded++
	case outcomeBlocked:
		b.Blocked++
	}
	// Refusals and errors are counted in the totals but not graphed: stacked
	// into a rare-event sliver they would be unreadable.
	b.LatencySum += uint64(d.Milliseconds())
	b.LatencyCount++
}

func (h *history) addCache(hit bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b := h.current(h.now().Unix() / 60)
	if hit {
		b.CacheHits++
	} else {
		b.CacheMisses++
	}
}

// snapshot returns exactly histSlots buckets ending at the current minute, in
// chronological order. Minutes with no traffic come back as zero samples rather
// than being omitted, so the chart's x axis is evenly spaced and a quiet period
// draws as a floor instead of a straight line through the gap.
func (h *history) snapshot() []Bucket {
	nowMin := h.now().Unix() / 60
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Bucket, 0, histSlots)
	for i := int64(histSlots - 1); i >= 0; i-- {
		m := nowMin - i
		if b := h.slots[m%histSlots]; b.Minute == m {
			out = append(out, b)
			continue
		}
		out = append(out, Bucket{Minute: m})
	}
	return out
}
