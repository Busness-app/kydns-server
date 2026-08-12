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
