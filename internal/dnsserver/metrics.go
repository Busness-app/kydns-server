package dnsserver

import (
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// outcome is what the pipeline did with a query. Every reply lands in exactly
// one, so the outcomes always sum to the total.
type outcome int

const (
	outcomeError outcome = iota // malformed, wrong opcode, wrong class, no forwarder
	outcomeAuthoritative
	outcomeForwarded
	outcomeBlocked
	outcomeRefused
)

// outcomeFor maps the pipeline's source label onto an outcome. The labels are
// the query log's, so they stay the vocabulary rather than growing a parallel
// one; anything unrecognized is an error, which keeps the sum honest.
func outcomeFor(source string) outcome {
	switch source {
	case "authoritative":
		return outcomeAuthoritative
	case "forward":
		return outcomeForwarded
	case "blocked":
		return outcomeBlocked
	case "acl":
		return outcomeRefused
	}
	return outcomeError
}

// MetricsSnapshot is a point-in-time read. It is counts and timestamps only —
// no name, no address — so serving it never depends on the log_client_ip gate.
type MetricsSnapshot struct {
	Total         uint64 `json:"total"`
	Authoritative uint64 `json:"authoritative"`
	Forwarded     uint64 `json:"forwarded"`
	Blocked       uint64 `json:"blocked"`
	Refused       uint64 `json:"refused"`
	Errors        uint64 `json:"errors"`

	NoError  uint64 `json:"noerror"`
	NXDomain uint64 `json:"nxdomain"`
	ServFail uint64 `json:"servfail"`

	CacheHits   uint64 `json:"cache_hits"`
	CacheMisses uint64 `json:"cache_misses"`

	LatencySum   uint64 `json:"latency_sum_ms"`
	LatencyCount uint64 `json:"latency_count"`

	LastQuery     int64 `json:"last_query"` // unix seconds, 0 if never
	UptimeSeconds int64 `json:"uptime_seconds"`

	History []Bucket `json:"history"`
}

// AvgMS is the mean response time over the process lifetime, 0 before the first
// query.
func (s MetricsSnapshot) AvgMS() int64 {
	if s.LatencyCount == 0 {
		return 0
	}
	return int64(s.LatencySum / s.LatencyCount)
}

// CacheHitRate is the percentage of forwarded lookups the cache answered.
func (s MetricsSnapshot) CacheHitRate() int {
	total := s.CacheHits + s.CacheMisses
	if total == 0 {
		return 0
	}
	return int(s.CacheHits * 100 / total)
}

// Metrics counts what the server did. It exists because the dashboard could
// previously only show configuration and failures: a server answering happily
// looked identical to one answering nothing.
type Metrics struct {
	total, authoritative, forwarded, blocked, refused, errs atomic.Uint64
	noerror, nxdomain, servfail                             atomic.Uint64
	cacheHits, cacheMisses                                  atomic.Uint64
	latSum, latCount                                        atomic.Uint64
	lastQuery                                               atomic.Int64

	started time.Time
	hist    *history
	now     func() time.Time
}

func NewMetrics() *Metrics { return newMetrics(time.Now) }

func newMetrics(now func() time.Time) *Metrics {
	if now == nil {
		now = time.Now
	}
	return &Metrics{started: now(), hist: newHistory(now), now: now}
}

// Record files one reply. It is called from the single closure every path in
// ServeDNS returns through, so no outcome can go uncounted.
func (m *Metrics) Record(source string, rcode int, d time.Duration) {
	if m == nil {
		return
	}
	o := outcomeFor(source)
	m.total.Add(1)
	switch o {
	case outcomeAuthoritative:
		m.authoritative.Add(1)
	case outcomeForwarded:
		m.forwarded.Add(1)
	case outcomeBlocked:
		m.blocked.Add(1)
	case outcomeRefused:
		m.refused.Add(1)
	default:
		m.errs.Add(1)
	}
	switch rcode {
	case dns.RcodeSuccess:
		m.noerror.Add(1)
	case dns.RcodeNameError:
		m.nxdomain.Add(1)
	case dns.RcodeServerFailure:
		m.servfail.Add(1)
	}
	m.latSum.Add(uint64(d.Milliseconds()))
	m.latCount.Add(1)
	m.lastQuery.Store(m.now().Unix())
	m.hist.add(o, d)
}

// RecordCache files one cache lookup. The Cache calls it so the hit rate lives
// beside the query counts instead of needing a second read path.
func (m *Metrics) RecordCache(hit bool) {
	if m == nil {
		return
	}
	if hit {
		m.cacheHits.Add(1)
	} else {
		m.cacheMisses.Add(1)
	}
	m.hist.addCache(hit)
}

func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{History: newHistory(nil).snapshot()}
	}
	return MetricsSnapshot{
		Total:         m.total.Load(),
		Authoritative: m.authoritative.Load(),
		Forwarded:     m.forwarded.Load(),
		Blocked:       m.blocked.Load(),
		Refused:       m.refused.Load(),
		Errors:        m.errs.Load(),
		NoError:       m.noerror.Load(),
		NXDomain:      m.nxdomain.Load(),
		ServFail:      m.servfail.Load(),
		CacheHits:     m.cacheHits.Load(),
		CacheMisses:   m.cacheMisses.Load(),
		LatencySum:    m.latSum.Load(),
		LatencyCount:  m.latCount.Load(),
		LastQuery:     m.lastQuery.Load(),
		UptimeSeconds: int64(m.now().Sub(m.started).Seconds()),
		History:       m.hist.snapshot(),
	}
}
