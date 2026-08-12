package upstream

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

// pool keeps a few idle TLS connections alive. dns.Client dials a fresh
// connection per Exchange, which costs a full TLS handshake — two extra round
// trips to the upstream on every cache miss.
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
