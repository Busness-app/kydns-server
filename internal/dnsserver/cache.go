package dnsserver

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheKey struct {
	name  string
	qtype uint16
	do    bool
}

type cacheEntry struct {
	key     cacheKey
	msg     *dns.Msg
	stored  time.Time
	expires time.Time
	ttl     uint32
}

// Cache holds forwarded responses. Authoritative answers are never cached —
// they already live in the snapshot.
type Cache struct {
	mu         sync.Mutex
	entries    map[cacheKey]*list.Element
	order      *list.List // front is newest
	maxEntries int
	minTTL     uint32
	maxTTL     uint32
	negMaxTTL  uint32
	now        func() time.Time
}

func NewCache(maxEntries, minTTL, maxTTL, negMaxTTL int) *Cache {
	return &Cache{
		entries:    map[cacheKey]*list.Element{},
		order:      list.New(),
		maxEntries: maxEntries,
		minTTL:     uint32(minTTL),
		maxTTL:     uint32(maxTTL),
		negMaxTTL:  uint32(negMaxTTL),
		now:        time.Now,
	}
}

func keyFor(q dns.Question, do bool) cacheKey {
	return cacheKey{name: strings.ToLower(dns.Fqdn(q.Name)), qtype: q.Qtype, do: do}
}

// Get returns a copy of the cached message with TTLs decremented by age.
func (c *Cache) Get(q dns.Question, do bool) (*dns.Msg, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[keyFor(q, do)]
	if !ok {
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	now := c.now()
	if !now.Before(e.expires) {
		c.removeLocked(el)
		return nil, false
	}
	c.order.MoveToFront(el)
	age := uint32(now.Sub(e.stored).Seconds())
	out := e.msg.Copy()
	for _, section := range [][]dns.RR{out.Answer, out.Ns, out.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue // OPT's "TTL" field is EXTENDED-RCODE/VERSION/DO/Z, not a TTL
			}
			h := rr.Header()
			if h.Ttl > age {
				h.Ttl -= age
			} else {
				h.Ttl = 0
			}
		}
	}
	return out, true
}

// Put stores a response, clamping its TTL. Negative answers use the SOA
// MINIMUM per RFC 2308, clamped by negMaxTTL.
func (c *Cache) Put(q dns.Question, do bool, m *dns.Msg) {
	if m == nil {
		return
	}
	ttl := c.ttlFor(m)
	if ttl == 0 {
		return
	}
	stored := c.now()
	entry := &cacheEntry{
		key: keyFor(q, do), msg: m.Copy(), stored: stored,
		expires: stored.Add(time.Duration(ttl) * time.Second), ttl: ttl,
	}
	// Normalize stored TTLs so Get's age subtraction starts from the clamp.
	for _, section := range [][]dns.RR{entry.msg.Answer, entry.msg.Ns, entry.msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue // OPT's "TTL" field is EXTENDED-RCODE/VERSION/DO/Z, not a TTL
			}
			rr.Header().Ttl = ttl
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[entry.key]; ok {
		c.removeLocked(el)
	}
	c.entries[entry.key] = c.order.PushFront(entry)
	for c.order.Len() > c.maxEntries {
		c.removeLocked(c.order.Back())
	}
}

func (c *Cache) ttlFor(m *dns.Msg) uint32 {
	if m.Rcode == dns.RcodeNameError || len(m.Answer) == 0 {
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				return clamp(soa.Minttl, c.minTTL, c.negMaxTTL)
			}
		}
		return 0 // nothing authoritative to base a negative TTL on
	}
	lowest := ^uint32(0)
	for _, rr := range m.Answer {
		if t := rr.Header().Ttl; t < lowest {
			lowest = t
		}
	}
	return clamp(lowest, c.minTTL, c.maxTTL)
}

func clamp(v, lo, hi uint32) uint32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (c *Cache) removeLocked(el *list.Element) {
	if el == nil {
		return
	}
	delete(c.entries, el.Value.(*cacheEntry).key)
	c.order.Remove(el)
}

func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[cacheKey]*list.Element{}
	c.order.Init()
}

func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
