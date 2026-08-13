package upstream

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// pipeDialer returns a dial func that hands out one end of a net.Pipe per
// call, closing the other end via t.Cleanup so nothing leaks.
func pipeDialer(t *testing.T, dialed *int) func(context.Context) (*dns.Conn, error) {
	t.Helper()
	return func(context.Context) (*dns.Conn, error) {
		if dialed != nil {
			*dialed++
		}
		client, server := net.Pipe()
		t.Cleanup(func() { server.Close() })
		return &dns.Conn{Conn: client}, nil
	}
}

// Once closed, get must not dial a fresh connection to an upstream the
// operator just removed — it must fail instead.
func TestPoolGetAfterCloseReturnsErrorInsteadOfDialing(t *testing.T) {
	dialed := 0
	p := newPool(2, time.Minute, pipeDialer(t, &dialed))

	if err := p.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
	_, reused, err := p.get(context.Background())
	if err != errPoolClosed {
		t.Fatalf("get() after Close() error = %v, want errPoolClosed", err)
	}
	if reused {
		t.Error("get() after Close() reported reused = true")
	}
	if dialed != 0 {
		t.Errorf("get() after Close() dialed %d connections, want 0", dialed)
	}
}

// Once closed, put must close the connection handed back to it rather than
// enqueue it: nothing will ever drain the idle channel again, so enqueuing
// would leak the connection instead of the pool.
func TestPoolPutAfterCloseClosesTheConnection(t *testing.T) {
	p := newPool(2, time.Minute, pipeDialer(t, nil))
	client, server := net.Pipe()
	t.Cleanup(func() { server.Close() })
	conn := &dns.Conn{Conn: client}

	if err := p.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
	p.put(conn)

	select {
	case <-p.idle:
		t.Fatal("put() after Close() enqueued the connection instead of closing it")
	default:
	}
	// A closed net.Pipe end returns an error on the next read rather than
	// blocking, so this proves put() actually closed it.
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("connection is still open after put() following Close()")
	}
}

func TestPoolCloseOnEmptyPoolIsSafe(t *testing.T) {
	p := newPool(2, time.Minute, pipeDialer(t, nil))
	if err := p.Close(); err != nil {
		t.Errorf("Close() on an empty pool = %v, want nil", err)
	}
}

// Close must be idempotent: a second call must not double-close a
// connection the first call already drained.
func TestPoolCloseIsSafeToCallTwice(t *testing.T) {
	p := newPool(2, time.Minute, pipeDialer(t, nil))
	client, server := net.Pipe()
	t.Cleanup(func() { server.Close() })
	p.put(&dns.Conn{Conn: client})

	if err := p.Close(); err != nil {
		t.Fatalf("first Close() = %v, want nil", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close() = %v, want nil", err)
	}
}
