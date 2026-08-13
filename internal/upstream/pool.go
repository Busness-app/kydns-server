package upstream

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

// pool keeps a couple of idle TLS connections alive, so a query that arrives
// while one is spare skips the handshake dns.Client would otherwise pay per
// Exchange. It is not a burst buffer: measured, 50 concurrent exchanges dial
// 50 connections and close all but the two the idle list holds. Household
// query rates are sequential enough for that to be the common case.
//
// A config reload retires whole upstreams, which is why the pool has Close:
// without it, each retired dot's idle connections would sit open until the
// process exits.
type pool struct {
	idle chan *pooledConn
	dial func(context.Context) (*dns.Conn, error)
	ttl  time.Duration
	now  func() time.Time
}

type pooledConn struct {
	c       *dns.Conn
	expires time.Time
}

func newPool(size int, ttl time.Duration, dial func(context.Context) (*dns.Conn, error)) *pool {
	return &pool{idle: make(chan *pooledConn, size), dial: dial, ttl: ttl, now: time.Now}
}

// get returns an idle connection or dials a new one. reused reports which,
// because only a reused connection is worth retrying after a failure.
func (p *pool) get(ctx context.Context) (conn *dns.Conn, reused bool, err error) {
	for {
		select {
		case pc := <-p.idle:
			if p.now().Before(pc.expires) {
				return pc.c, true, nil
			}
			pc.c.Close()
		default:
			c, err := p.dial(ctx)
			return c, false, err
		}
	}
}

func (p *pool) put(c *dns.Conn) {
	select {
	case p.idle <- &pooledConn{c: c, expires: p.now().Add(p.ttl)}:
	default:
		c.Close()
	}
}

// Close closes every idle connection. Safe on an empty pool, and does not
// block on connections currently checked out by get().
func (p *pool) Close() error {
	var err error
	for {
		select {
		case pc := <-p.idle:
			if e := pc.c.Close(); e != nil && err == nil {
				err = e
			}
		default:
			return err
		}
	}
}
