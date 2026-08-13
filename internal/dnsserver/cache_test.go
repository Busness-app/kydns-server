package dnsserver

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func reply(name string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   []byte{192, 0, 2, 1},
	}}
	return m
}

func question(name string) dns.Question {
	return dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
}

func TestCacheRoundTrip(t *testing.T) {
	c := NewCache(10, 5, 3600, 300)
	q := question("a.example.com.")
	if _, ok := c.Get(q, false); ok {
		t.Fatal("Get() on an empty cache returned a hit")
	}
	c.Put(q, false, reply("a.example.com.", 300))
	m, ok := c.Get(q, false)
	if !ok {
		t.Fatal("Get() after Put() missed")
	}
	if len(m.Answer) != 1 {
		t.Fatalf("cached answer = %v", m.Answer)
	}
}

// The key is case-insensitive on qname, matching DNS semantics.
func TestCacheKeyIsCaseInsensitive(t *testing.T) {
	c := NewCache(10, 5, 3600, 300)
	c.Put(question("A.Example.COM."), false, reply("A.Example.COM.", 300))
	if _, ok := c.Get(question("a.example.com."), false); !ok {
		t.Error("Get() missed on a case-differing qname")
	}
}

func TestCacheClampsTTL(t *testing.T) {
	c := NewCache(10, 30, 120, 300)
	c.Put(question("low.example.com."), false, reply("low.example.com.", 5))
	m, _ := c.Get(question("low.example.com."), false)
	if ttl := m.Answer[0].Header().Ttl; ttl != 30 {
		t.Errorf("TTL = %d, want clamped up to the 30s minimum", ttl)
	}
	c.Put(question("high.example.com."), false, reply("high.example.com.", 9999))
	m, _ = c.Get(question("high.example.com."), false)
	if ttl := m.Answer[0].Header().Ttl; ttl != 120 {
		t.Errorf("TTL = %d, want clamped down to the 120s maximum", ttl)
	}
}

func TestCacheDecrementsTTLByAge(t *testing.T) {
	c := NewCache(10, 5, 3600, 300)
	now := time.Now()
	c.now = func() time.Time { return now }
	c.Put(question("a.example.com."), false, reply("a.example.com.", 100))

	now = now.Add(40 * time.Second)
	m, ok := c.Get(question("a.example.com."), false)
	if !ok {
		t.Fatal("entry expired early")
	}
	if ttl := m.Answer[0].Header().Ttl; ttl != 60 {
		t.Errorf("TTL = %d, want 60 after 40s of age", ttl)
	}
}

func TestCacheExpires(t *testing.T) {
	c := NewCache(10, 5, 3600, 300)
	now := time.Now()
	c.now = func() time.Time { return now }
	c.Put(question("a.example.com."), false, reply("a.example.com.", 30))

	now = now.Add(31 * time.Second)
	if _, ok := c.Get(question("a.example.com."), false); ok {
		t.Error("Get() returned an expired entry")
	}
}

func TestCacheCountsHitsAndMisses(t *testing.T) {
	c := NewCache(10, 5, 3600, 300)
	m := NewMetrics()
	c.SetMetrics(m)

	c.Get(question("a.example.com."), false) // miss
	c.Put(question("a.example.com."), false, reply("a.example.com.", 30))
	c.Get(question("a.example.com."), false) // hit
	c.Get(question("a.example.com."), false) // hit

	s := m.Snapshot()
	if s.CacheHits != 2 || s.CacheMisses != 1 {
		t.Errorf("hits/misses = %d/%d, want 2/1", s.CacheHits, s.CacheMisses)
	}
	if got := s.CacheHitRate(); got != 66 {
		t.Errorf("CacheHitRate() = %d, want 66", got)
	}
}

// An expired entry is a miss. Counting it as a hit would report a healthy hit
// rate on a cache that is actually forwarding every query.
func TestCacheExpiredLookupCountsAsMiss(t *testing.T) {
	c := NewCache(10, 5, 3600, 300)
	m := NewMetrics()
	c.SetMetrics(m)
	now := time.Now()
	c.now = func() time.Time { return now }
	c.Put(question("a.example.com."), false, reply("a.example.com.", 30))

	now = now.Add(31 * time.Second)
	c.Get(question("a.example.com."), false)

	if s := m.Snapshot(); s.CacheHits != 0 || s.CacheMisses != 1 {
		t.Errorf("hits/misses = %d/%d, want 0/1", s.CacheHits, s.CacheMisses)
	}
}

// RFC 2308: negative answers are cached using the SOA MINIMUM, clamped by
// negMaxTTL.
func TestNegativeCachingUsesSOAMinimum(t *testing.T) {
	c := NewCache(10, 5, 3600, 60)
	m := new(dns.Msg)
	m.Rcode = dns.RcodeNameError
	m.Ns = []dns.RR{&dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Minttl: 900,
	}}
	q := question("nope.example.com.")
	now := time.Now()
	c.now = func() time.Time { return now }
	c.Put(q, false, m)

	if _, ok := c.Get(q, false); !ok {
		t.Fatal("negative answer was not cached at all")
	}
	now = now.Add(70 * time.Second)
	if _, ok := c.Get(q, false); ok {
		t.Error("negative entry outlived the clamped 60s maximum")
	}
}

// A negative answer with no SOA has no basis for a TTL and must not be cached.
func TestNegativeWithoutSOANotCached(t *testing.T) {
	c := NewCache(10, 5, 3600, 60)
	m := new(dns.Msg)
	m.Rcode = dns.RcodeNameError
	q := question("nope.example.com.")
	c.Put(q, false, m)
	if _, ok := c.Get(q, false); ok {
		t.Error("cached a negative answer with no SOA to derive a TTL from")
	}
}

func TestCacheEvictsOldest(t *testing.T) {
	c := NewCache(2, 5, 3600, 300)
	for _, n := range []string{"a.example.com.", "b.example.com.", "c.example.com."} {
		c.Put(question(n), false, reply(n, 300))
	}
	if c.Len() > 2 {
		t.Errorf("Len() = %d, want at most 2", c.Len())
	}
	if _, ok := c.Get(question("c.example.com."), false); !ok {
		t.Error("the newest entry was evicted")
	}
}

func TestCacheFlush(t *testing.T) {
	c := NewCache(10, 5, 3600, 300)
	c.Put(question("a.example.com."), false, reply("a.example.com.", 300))
	c.Flush()
	if c.Len() != 0 {
		t.Errorf("Len() = %d after Flush(), want 0", c.Len())
	}
}

// A caller mutating a returned message must not corrupt the cached copy.
func TestCacheReturnsCopy(t *testing.T) {
	c := NewCache(10, 5, 3600, 300)
	q := question("a.example.com.")
	c.Put(q, false, reply("a.example.com.", 300))
	first, _ := c.Get(q, false)
	first.Answer[0].Header().Ttl = 1

	second, _ := c.Get(q, false)
	if second.Answer[0].Header().Ttl == 1 {
		t.Error("Get() handed out the cached message; a caller mutated it")
	}
}

// A DO=1 client wants RRSIGs and a DO=0 client does not, so the two responses
// are different messages and must not share an entry.
func TestCacheSeparatesByDOBit(t *testing.T) {
	c := NewCache(10, 5, 3600, 300)
	q := question("a.example.com.")

	c.Put(q, true, reply("a.example.com.", 300))
	if _, ok := c.Get(q, false); ok {
		t.Error("Get(do=false) hit an entry stored with do=true")
	}
	if _, ok := c.Get(q, true); !ok {
		t.Error("Get(do=true) missed its own entry")
	}

	c.Put(q, false, reply("a.example.com.", 300))
	if _, ok := c.Get(q, false); !ok {
		t.Error("Get(do=false) missed after its own Put")
	}
}

// The OPT record's "TTL" field is not a TTL (RFC 6891 section 6.1.3): it packs
// EXTENDED-RCODE, VERSION, DO, and Z. Both the clamp-on-Put and the
// age-decrement-on-Get loops must leave it alone, or a cached response hands
// out a forged DO bit and OPT version. A large cache_max_ttl (operator
// reachable) exercises the version byte, not just the DO bit.
func TestCachePreservesOPTRecord(t *testing.T) {
	c := NewCache(10, 5, 86400, 300)
	q := question("a.example.com.")
	m := reply("a.example.com.", 300)
	m.SetEdns0(1232, true)

	c.Put(q, true, m)
	out, ok := c.Get(q, true)
	if !ok {
		t.Fatal("Get() after Put() missed")
	}
	opt := out.IsEdns0()
	if opt == nil {
		t.Fatal("cached response lost its OPT record")
	}
	if !opt.Do() {
		t.Error("cached response lost the DO bit")
	}
	if opt.Version() != 0 {
		t.Errorf("OPT version = %d, want 0", opt.Version())
	}
}

// TestCachePreservesOPTRecord above stores and fetches with no elapsed time,
// so age is 0 and Get's "h.Ttl -= age" is a no-op regardless of whether OPT
// is skipped — it does not exercise Get's own guard. This test forces a
// nonzero age so Get's age-decrement loop actually runs against the OPT
// record, not just Put's clamp loop.
func TestCacheGetPreservesOPTRecordAfterAgeDecrement(t *testing.T) {
	c := NewCache(10, 5, 86400, 300)
	now := time.Now()
	c.now = func() time.Time { return now }
	q := question("a.example.com.")
	m := reply("a.example.com.", 300)
	m.SetEdns0(1232, true)
	c.Put(q, true, m)

	now = now.Add(40 * time.Second)
	out, ok := c.Get(q, true)
	if !ok {
		t.Fatal("entry expired early")
	}
	opt := out.IsEdns0()
	if opt == nil {
		t.Fatal("cached response lost its OPT record after aging")
	}
	if !opt.Do() {
		t.Error("cached response lost the DO bit after aging")
	}
	if opt.Version() != 0 {
		t.Errorf("OPT version = %d after aging, want 0", opt.Version())
	}
}

func TestCacheRetuneShrinks(t *testing.T) {
	c := NewCache(10, 1, 3600, 300)
	for i := 0; i < 10; i++ {
		name := question("h" + string(rune('a'+i)) + ".example.")
		c.Put(name, false, reply(name.Name, 60))
	}
	if c.Len() != 10 {
		t.Fatalf("cache holds %d, want 10", c.Len())
	}

	// Shrinking must evict down immediately, not wait for the next insert:
	// an operator lowering this is reclaiming memory now.
	c.Retune(3, 1, 3600, 300)
	if c.Len() > 3 {
		t.Errorf("cache still holds %d after shrinking to 3", c.Len())
	}
}

func TestCacheRetuneChangesClamp(t *testing.T) {
	c := NewCache(10, 1, 3600, 300)
	q := question("a.example.")

	c.Retune(10, 1, 10, 300)
	c.Put(q, false, reply(q.Name, 3000))

	got, ok := c.Get(q, false)
	if !ok {
		t.Fatal("entry missing")
	}
	if got.Answer[0].Header().Ttl > 10 {
		t.Errorf("TTL %d exceeds the new maximum of 10", got.Answer[0].Header().Ttl)
	}
}

// Put's eviction loop assumes maxEntries is positive: with a non-positive
// value, order.Len() > maxEntries never goes false, and Put spins forever.
// Retune is the first API that can set maxEntries at runtime, so it must
// clamp rather than trust the caller.
func TestCacheRetuneClampsNonPositiveMaxEntries(t *testing.T) {
	c := NewCache(10, 1, 3600, 300)
	c.Retune(-1, 1, 3600, 300)

	done := make(chan struct{})
	go func() {
		c.Put(question("a.example."), false, reply("a.example.", 60))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Put did not return after Retune(-1, ...): the eviction loop is spinning")
	}
	if c.Len() != 1 {
		t.Errorf("cache holds %d after Retune(-1, ...) and one Put, want 1", c.Len())
	}
}
