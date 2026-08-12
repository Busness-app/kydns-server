package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
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

// Forwarder resolves non-authoritative queries through the cache and, on a
// miss, the upstream list in order.
type Forwarder struct {
	ups     []upstream.Upstream
	timeout time.Duration
	cache   *Cache
	group   singleflight.Group

	mu     sync.Mutex
	status []UpstreamStatus
}

func NewForwarder(ups []upstream.Upstream, timeout time.Duration, c *Cache) *Forwarder {
	f := &Forwarder{ups: ups, timeout: timeout, cache: c, status: make([]UpstreamStatus, len(ups))}
	for i, u := range ups {
		f.status[i] = UpstreamStatus{Spec: u.String(), Secure: u.Secure()}
	}
	return f
}

// Status is a snapshot for the UI, copied so callers cannot race the recorder.
func (f *Forwarder) Status() []UpstreamStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]UpstreamStatus(nil), f.status...)
}

func (f *Forwarder) record(i int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		f.status[i].LastError = err.Error()
		f.status[i].LastErrAt = time.Now()
		return
	}
	f.status[i].LastError = ""
	f.status[i].LastErrAt = time.Time{}
	f.status[i].LastOKAt = time.Now()
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

	if len(f.ups) == 0 {
		return nil, errors.New("no upstreams configured")
	}
	var lastErr error
	for i, u := range f.ups {
		attempt, cancel := context.WithTimeout(ctx, f.timeout)
		resp, err := u.Exchange(attempt, req)
		cancel()
		if err == nil && resp != nil && resp.Rcode != dns.RcodeServerFailure {
			if !u.Secure() {
				// Cleared here rather than at the response boundary, so a
				// plaintext answer cannot carry AD into the cache either.
				resp.AuthenticatedData = false
			}
			f.record(i, nil)
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
		f.record(i, errors.New(reason))
	}
	return nil, fmt.Errorf("all upstreams failed: %w", lastErr)
}
