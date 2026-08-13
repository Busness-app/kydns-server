package dnsserver

import (
	"testing"
	"time"
)

// atMinute is a clock pinned to the start of minute n of an arbitrary hour.
func atMinute(base time.Time, n int) time.Time {
	return base.Add(time.Duration(n) * time.Minute)
}

func TestHistoryBucketsByMinute(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).Truncate(time.Minute)
	now := base
	h := newHistory(func() time.Time { return now })

	h.add(outcomeAuthoritative, 5*time.Millisecond)
	now = atMinute(base, 1)
	h.add(outcomeForwarded, 5*time.Millisecond)
	h.add(outcomeForwarded, 5*time.Millisecond)

	got := h.snapshot()
	if n := len(got); n != histSlots {
		t.Fatalf("snapshot has %d buckets, want %d", n, histSlots)
	}
	last := got[histSlots-1]
	if last.Forwarded != 2 {
		t.Errorf("current minute Forwarded = %d, want 2", last.Forwarded)
	}
	prev := got[histSlots-2]
	if prev.Authoritative != 1 {
		t.Errorf("previous minute Authoritative = %d, want 1", prev.Authoritative)
	}
}

// The ring is lazily reset, so a slot last written an hour ago must read as an
// empty minute. Reporting hour-old traffic as current is the one failure that
// would make the graph actively lie.
func TestHistoryStaleSlotReadsAsEmpty(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).Truncate(time.Minute)
	now := base
	h := newHistory(func() time.Time { return now })

	h.add(outcomeForwarded, time.Millisecond)
	now = atMinute(base, histSlots) // exactly one full lap later

	got := h.snapshot()
	for i, b := range got {
		if b.Forwarded != 0 {
			t.Fatalf("bucket %d still reports %d forwarded a full lap later", i, b.Forwarded)
		}
	}
	if last := got[histSlots-1]; last.Minute != now.Unix()/60 {
		t.Errorf("last bucket minute = %d, want %d", last.Minute, now.Unix()/60)
	}
}

// A gap in traffic is real information: those minutes must come back as zero
// samples, not be dropped so the chart interpolates straight through them.
func TestHistoryGapIsZeroNotMissing(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).Truncate(time.Minute)
	now := base
	h := newHistory(func() time.Time { return now })

	h.add(outcomeForwarded, time.Millisecond)
	now = atMinute(base, 3)
	h.add(outcomeForwarded, time.Millisecond)

	got := h.snapshot()
	for i := histSlots - 3; i < histSlots-1; i++ {
		if got[i].Forwarded != 0 {
			t.Errorf("bucket %d = %d, want a zero sample", i, got[i].Forwarded)
		}
	}
	if got[histSlots-4].Forwarded != 1 {
		t.Errorf("the older sample was lost: %+v", got[histSlots-4])
	}
	// Every minute is present and strictly increasing, so the x axis is even.
	for i := 1; i < len(got); i++ {
		if got[i].Minute != got[i-1].Minute+1 {
			t.Fatalf("bucket %d minute %d does not follow %d", i, got[i].Minute, got[i-1].Minute)
		}
	}
}

func TestHistoryCountsCacheHitsPerMinute(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).Truncate(time.Minute)
	now := base
	h := newHistory(func() time.Time { return now })

	h.addCache(true)
	h.addCache(true)
	h.addCache(false)

	last := h.snapshot()[histSlots-1]
	if last.CacheHits != 2 || last.CacheMisses != 1 {
		t.Errorf("hits/misses = %d/%d, want 2/1", last.CacheHits, last.CacheMisses)
	}
}
