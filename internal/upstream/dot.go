package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// dotIdle is how long a spare connection is worth keeping. RFC 7858 servers
// commonly drop idle connections after about ten seconds.
const dotIdle = 10 * time.Second

// dotIdleConns is deliberately small: a household's query rate is low, and each
// spare connection is a socket held open at the provider.
const dotIdleConns = 2

type dot struct {
	spec    Spec
	timeout time.Duration
	pool    *pool
}

func newDoT(s Spec, timeout time.Duration) *dot {
	client := &dns.Client{Net: "tcp-tls", Timeout: timeout, TLSConfig: tlsConfig(s)}
	return &dot{
		spec:    s,
		timeout: timeout,
		pool: newPool(dotIdleConns, dotIdle, func(ctx context.Context) (*dns.Conn, error) {
			return client.DialContext(ctx, s.Addr)
		}),
	}
}

func (d *dot) Secure() bool   { return true }
func (d *dot) String() string { return d.spec.Raw }
func (d *dot) Close() error   { return d.pool.Close() }

// Exchange retries once per pooled connection it finds already dead — up to
// the pool's size — because the server may have closed it while it sat idle.
// A fresh connection that fails is a real failure. Cancellation is honoured
// at entry, and thereafter only via the deadline each connection is given:
// a context cancelled mid-read is not itself watched, matching plain's
// dns.Client.ExchangeContext, which behaves the same way.
func (d *dot) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for {
		conn, reused, err := d.pool.get(ctx)
		if err != nil {
			return nil, err
		}
		resp, err := d.roundTrip(ctx, conn, m)
		if err == nil {
			d.pool.put(conn)
			return resp, nil
		}
		conn.Close()
		if !reused {
			return nil, err
		}
	}
}

func (d *dot) roundTrip(ctx context.Context, conn *dns.Conn, m *dns.Msg) (*dns.Msg, error) {
	deadline := time.Now().Add(d.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := conn.WriteMsg(m); err != nil {
		return nil, err
	}
	resp, err := conn.ReadMsg()
	if err != nil {
		return nil, err
	}
	// One query per connection at a time, so a mismatched id is not a
	// pipelined reply — it is the wrong answer.
	if resp.Id != m.Id {
		return nil, fmt.Errorf("upstream %s: reply id %d does not match query %d", d.spec.Raw, resp.Id, m.Id)
	}
	return resp, nil
}

// tlsConfig verifies the peer against ServerName when one was configured, and
// against the dialled IP otherwise. There is deliberately no way to skip it.
func tlsConfig(s Spec) *tls.Config {
	name := s.ServerName
	if name == "" {
		if host, _, err := net.SplitHostPort(s.Addr); err == nil {
			name = host
		}
	}
	return &tls.Config{ServerName: name, RootCAs: s.RootCAs, MinVersion: tls.VersionTLS12}
}
