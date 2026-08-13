package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/yoshiofthewire/kydns-server/internal/upstream"
	"golang.org/x/sync/singleflight"
)

// UpstreamStatus is what the last query to one upstream did. Without it, a
// firewall that blocks port 853 presents to the operator as "DNS is broken".
type UpstreamStatus struct {
	Spec      string
	Secure    bool
	LastError string
	LastErrAt time.Time
	LastOKAt  time.Time
}

// fwdState pairs the upstream list with its status slice. They are only ever
// swapped together, so an in-flight query cannot record a result against an
// upstream that is no longer at that index.
type fwdState struct {
	ups []upstream.Upstream

	mu     sync.Mutex
	status []UpstreamStatus
}

// close releases every upstream's connections. Only called once this state
// has been retired by a swap.
func (st *fwdState) close() {
	for _, u := range st.ups {
		u.Close()
	}
}

// Forwarder resolves non-authoritative queries through the cache and, on a
// miss, the upstream list in order.
type Forwarder struct {
	state   atomic.Pointer[fwdState]
	timeout time.Duration
	cache   *Cache
	group   singleflight.Group
}

func NewForwarder(ups []upstream.Upstream, timeout time.Duration, c *Cache) *Forwarder {
	f := &Forwarder{timeout: timeout, cache: c}
	f.Replace(ups)
	return f
}

// Replace swaps the upstream list. Status starts clean: the new upstreams
// have never been tried, and a stale error would send the operator after a
// problem that no longer exists.
//
// A query already in flight loaded the retiring state before this call and
// may still be mid-exchange on one of its connections, so the retired
// upstreams are not closed synchronously here. exchange loops over at most
// len(old.ups) attempts, each bounded by f.timeout, so closing after that
// worst case has elapsed is enough to guarantee no in-flight exchange is
// still using them. A goroutine that raced past its context deadline right
// at that boundary could in principle still be holding a connection; this is
// a bounded, best-effort guarantee, not a proof.
func (f *Forwarder) Replace(ups []upstream.Upstream) {
	st := &fwdState{ups: ups, status: make([]UpstreamStatus, len(ups))}
	for i, u := range ups {
		st.status[i] = UpstreamStatus{Spec: u.String(), Secure: u.Secure()}
	}
	old := f.state.Swap(st)
	if old != nil && len(old.ups) > 0 {
		time.AfterFunc(time.Duration(len(old.ups))*f.timeout, old.close)
	}
}

// Status is a snapshot for the UI, copied so callers cannot race the recorder.
func (f *Forwarder) Status() []UpstreamStatus {
	st := f.state.Load()
	st.mu.Lock()
	defer st.mu.Unlock()
	return append([]UpstreamStatus(nil), st.status...)
}

// record writes against the state the query started with. A result arriving
// after a swap lands on the retired object and is discarded with it, which is
// correct: it describes upstreams that are no longer configured.
func (st *fwdState) record(i int, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if err != nil {
		st.status[i].LastError = err.Error()
		st.status[i].LastErrAt = time.Now()
		return
	}
	st.status[i].LastError = ""
	st.status[i].LastErrAt = time.Time{}
	st.status[i].LastOKAt = time.Now()
}

// Resolve answers from cache, or collapses concurrent identical misses into a
// single upstream query. That collapse is what survives the boot-time
// stampede when every device on the LAN wakes at once.
func (f *Forwarder) Resolve(ctx context.Context, q dns.Question, do bool) (*dns.Msg, error) {
	if m, ok := f.cache.Get(q, do); ok {
		return m, nil
	}
	key := fmt.Sprintf("%s|%d|%t", strings.ToLower(dns.Fqdn(q.Name)), q.Qtype, do)
	v, err, _ := f.group.Do(key, func() (any, error) {
		if m, ok := f.cache.Get(q, do); ok {
			return m, nil
		}
		m, err := f.exchange(ctx, q, do)
		if err != nil {
			return nil, err
		}
		f.cache.Put(q, do, m)
		return m, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*dns.Msg).Copy(), nil
}

func (f *Forwarder) exchange(ctx context.Context, q dns.Question, do bool) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(q.Name), q.Qtype)
	req.SetEdns0(1232, do)
	// The upstream is the validator, so it is never told to skip checking, and
	// AD asks for its verdict without the RRSIG payload (RFC 6840 5.7).
	req.CheckingDisabled = false
	req.AuthenticatedData = true

	st := f.state.Load()
	if len(st.ups) == 0 {
		return nil, errors.New("no upstreams configured")
	}
	var lastErr error
	for i, u := range st.ups {
		attempt, cancel := context.WithTimeout(ctx, f.timeout)
		resp, err := u.Exchange(attempt, req)
		cancel()
		if err == nil && resp != nil && resp.Rcode != dns.RcodeServerFailure {
			if !u.Secure() {
				// Cleared here rather than at the response boundary, so a
				// plaintext answer cannot carry AD into the cache either.
				resp.AuthenticatedData = false
			}
			st.record(i, nil)
			return resp, nil
		}
		var reason string // bare: Status.Spec already names the upstream
		switch {
		case err != nil:
			reason = err.Error()
			lastErr = err
		case resp == nil:
			reason = "returned no message"
			lastErr = fmt.Errorf("upstream %s %s", u, reason)
		default:
			reason = "returned " + dns.RcodeToString[resp.Rcode]
			lastErr = fmt.Errorf("upstream %s %s", u, reason)
		}
		// record keeps the bare reason so the UI doesn't print the upstream
		// twice in adjacent columns; lastErr keeps the spec prefix, since the
		// aggregate error below has no such column to lean on.
		st.record(i, errors.New(reason))
	}
	return nil, fmt.Errorf("all upstreams failed: %w", lastErr)
}
