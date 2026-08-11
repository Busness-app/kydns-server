package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// Exchanger sends one query to one upstream. The interface exists so tests do
// not need real sockets, and so DoT or DoH can be added as another
// implementation without touching the handler.
type Exchanger interface {
	Exchange(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error)
}

// UDPExchanger is the plain UDP/TCP client. A truncated UDP reply is retried
// over TCP.
type UDPExchanger struct{ Timeout time.Duration }

func (u UDPExchanger) Exchange(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
	udp := &dns.Client{Net: "udp", Timeout: u.Timeout}
	resp, _, err := udp.ExchangeContext(ctx, m, addr)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: u.Timeout}
		resp, _, err = tcp.ExchangeContext(ctx, m, addr)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// Forwarder resolves non-authoritative queries through the cache and, on a
// miss, the upstream list in order.
type Forwarder struct {
	upstreams []string
	timeout   time.Duration
	cache     *Cache
	x         Exchanger
	group     singleflight.Group
}

func NewForwarder(upstreams []string, timeout time.Duration, c *Cache, x Exchanger) *Forwarder {
	return &Forwarder{upstreams: upstreams, timeout: timeout, cache: c, x: x}
}

func (f *Forwarder) Upstreams() []string { return f.upstreams }

// Resolve answers from cache, or collapses concurrent identical misses into a
// single upstream query. That collapse is what survives the boot-time
// stampede when every device on the LAN wakes at once.
func (f *Forwarder) Resolve(ctx context.Context, q dns.Question) (*dns.Msg, error) {
	if m, ok := f.cache.Get(q); ok {
		return m, nil
	}
	key := fmt.Sprintf("%s|%d", strings.ToLower(dns.Fqdn(q.Name)), q.Qtype)
	v, err, _ := f.group.Do(key, func() (any, error) {
		if m, ok := f.cache.Get(q); ok {
			return m, nil
		}
		m, err := f.exchange(ctx, q)
		if err != nil {
			return nil, err
		}
		f.cache.Put(q, m)
		return m, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*dns.Msg).Copy(), nil
}

func (f *Forwarder) exchange(ctx context.Context, q dns.Question) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(q.Name), q.Qtype)
	req.SetEdns0(1232, false)

	if len(f.upstreams) == 0 {
		return nil, errors.New("no upstreams configured")
	}
	var lastErr error
	for _, addr := range f.upstreams {
		attempt, cancel := context.WithTimeout(ctx, f.timeout)
		resp, err := f.x.Exchange(attempt, req, addr)
		cancel()
		if err == nil && resp != nil && resp.Rcode != dns.RcodeServerFailure {
			return resp, nil
		}
		if err != nil {
			lastErr = err
		} else if resp == nil {
			lastErr = fmt.Errorf("upstream %s returned no message", addr)
		} else {
			lastErr = fmt.Errorf("upstream %s returned %s", addr, dns.RcodeToString[resp.Rcode])
		}
	}
	return nil, fmt.Errorf("all upstreams failed: %w", lastErr)
}
