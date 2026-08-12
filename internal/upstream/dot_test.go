package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// dotServer starts an in-process DNS-over-TLS server. handshakes counts TLS
// handshakes, which is how the reuse test proves the pool is doing its job.
func dotServer(t *testing.T, cert tls.Certificate, idle time.Duration, h dns.HandlerFunc) (addr string, handshakes *atomic.Int64) {
	t.Helper()
	handshakes = new(atomic.Int64)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			handshakes.Add(1)
			return nil, nil
		},
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: l, Net: "tcp-tls", Handler: h}
	if idle > 0 {
		srv.IdleTimeout = func() time.Duration { return idle }
	}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return l.Addr().String(), handshakes
}

func dotSpec(addr string, pool *x509.CertPool) Spec {
	return Spec{Raw: "tls://" + addr, Transport: DoT, Addr: addr, RootCAs: pool}
}

func TestDoTRoundTrip(t *testing.T) {
	cert, pool := testCert(t)
	addr, _ := dotServer(t, cert, 0, func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) })

	u, err := New(dotSpec(addr, pool), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !u.Secure() {
		t.Error("Secure() = false for DoT")
	}
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
}

// A certificate signed by an unknown authority must fail. There is no option
// anywhere to accept it.
func TestDoTRejectsUntrustedCertificate(t *testing.T) {
	cert, _ := testCert(t)
	addr, _ := dotServer(t, cert, 0, func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) })

	other := x509.NewCertPool() // trusts nothing the server can present
	u, _ := New(dotSpec(addr, other), 2*time.Second)
	if _, err := u.Exchange(context.Background(), query()); err == nil {
		t.Fatal("Exchange() error = nil against an untrusted certificate")
	} else if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("error = %v, want it to name the certificate", err)
	}
}

// The pool exists so a cache miss does not cost a TLS handshake.
func TestDoTReusesConnections(t *testing.T) {
	cert, pool := testCert(t)
	addr, handshakes := dotServer(t, cert, 0, func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) })

	u, _ := New(dotSpec(addr, pool), 2*time.Second)
	for i := 0; i < 5; i++ {
		resp, err := u.Exchange(context.Background(), query())
		wantAnswer(t, resp, err)
	}
	if got := handshakes.Load(); got != 1 {
		t.Errorf("TLS handshakes = %d, want 1 reused connection", got)
	}
}

// A pooled connection the server has since closed must be retried once.
func TestDoTRetriesAfterServerClosesIdleConnection(t *testing.T) {
	cert, pool := testCert(t)
	addr, handshakes := dotServer(t, cert, time.Millisecond,
		func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) })

	u, _ := New(dotSpec(addr, pool), 2*time.Second)
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)

	time.Sleep(50 * time.Millisecond) // let the server drop the idle connection

	resp, err = u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
	if got := handshakes.Load(); got != 2 {
		t.Errorf("TLS handshakes = %d, want 2 (the dead connection redialled once)", got)
	}
}

// A connection that was never pooled gets no retry, or a dead upstream loops.
func TestDoTDoesNotRetryAFreshConnection(t *testing.T) {
	cert, pool := testCert(t)
	addr, _ := dotServer(t, cert, 0, func(w dns.ResponseWriter, r *dns.Msg) {
		w.Close() // hang up without replying
	})

	u, _ := New(dotSpec(addr, pool), 500*time.Millisecond)
	done := make(chan error, 1)
	go func() {
		_, err := u.Exchange(context.Background(), query())
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Exchange() error = nil against a server that hangs up")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Exchange() never returned: the retry is looping")
	}
}

func TestPoolExpiresIdleConnections(t *testing.T) {
	cert, pool := testCert(t)
	addr, handshakes := dotServer(t, cert, 0, func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) })

	d := newDoT(dotSpec(addr, pool), 2*time.Second)
	d.pool.ttl = 0 // every returned connection is already stale
	for i := 0; i < 3; i++ {
		resp, err := d.Exchange(context.Background(), query())
		wantAnswer(t, resp, err)
	}
	if got := handshakes.Load(); got != 3 {
		t.Errorf("TLS handshakes = %d, want 3 with expiry forced on", got)
	}
}

// ServerName lets a spec dial an IP while verifying a hostname — the
// #servername feature parse.go's bootstrapHint points users at. tlsConfig
// falls back to the dialled address only when ServerName is empty, so this
// must be exercised with one set, or the fallback would mask a broken
// ServerName plumb-through.
func TestDoTVerifiesServerName(t *testing.T) {
	cert, pool := testCert(t, "dns.example.test")
	addr, _ := dotServer(t, cert, 0, func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) })

	spec := dotSpec(addr, pool)
	spec.ServerName = "dns.example.test"
	u, err := New(spec, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
}

// A ServerName that does not match the certificate must fail verification,
// the same as any other untrusted peer.
func TestDoTRejectsServerNameMismatch(t *testing.T) {
	cert, pool := testCert(t, "dns.example.test")
	addr, _ := dotServer(t, cert, 0, func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) })

	spec := dotSpec(addr, pool)
	spec.ServerName = "wrong.example.test"
	u, _ := New(spec, 2*time.Second)
	if _, err := u.Exchange(context.Background(), query()); err == nil {
		t.Fatal("Exchange() error = nil with a ServerName that does not match the certificate")
	}
}

// An already-cancelled context must fail fast without touching the pool.
// Otherwise a client that times out costs the pool a live connection and a
// redial on every subsequent query.
func TestDoTExpiredContextDoesNotConsumePooledConnection(t *testing.T) {
	cert, pool := testCert(t)
	addr, handshakes := dotServer(t, cert, 0, func(w dns.ResponseWriter, r *dns.Msg) { w.WriteMsg(answer(r)) })

	u, _ := New(dotSpec(addr, pool), 2*time.Second)
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := u.Exchange(ctx, query()); !errors.Is(err, context.Canceled) {
		t.Errorf("Exchange() error = %v, want context.Canceled", err)
	}

	resp, err = u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
	if got := handshakes.Load(); got != 1 {
		t.Errorf("TLS handshakes = %d, want 1 (the pooled connection must survive an expired-context Exchange)", got)
	}
}

// A reply whose id does not match the query must be rejected, not returned
// to the caller as if it answered the question asked.
func TestDoTRejectsMismatchedReplyID(t *testing.T) {
	cert, pool := testCert(t)
	addr, _ := dotServer(t, cert, 0, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := answer(r)
		resp.Id++
		w.WriteMsg(resp)
	})

	u, _ := New(dotSpec(addr, pool), 2*time.Second)
	if _, err := u.Exchange(context.Background(), query()); err == nil {
		t.Fatal("Exchange() error = nil with a mismatched reply id")
	} else if !strings.Contains(err.Error(), "id") {
		t.Errorf("error = %v, want it to name the id mismatch", err)
	}
}
