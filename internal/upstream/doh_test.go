package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func dohServer(t *testing.T, cert tls.Certificate, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// dohEcho replies with the standard answer and records what it received.
func dohEcho(t *testing.T, seen *dns.Msg) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, dns.MaxMsgSize))
		if err != nil {
			t.Error(err)
			return
		}
		if err := seen.Unpack(body); err != nil {
			t.Error(err)
			return
		}
		wire, err := answer(seen).Pack()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(wire)
	}
}

// exactSizedWire is the standard answer padded with EDNS0 padding (RFC 7830)
// to exactly size bytes on the wire, so the answer section stays intact.
func exactSizedWire(t *testing.T, size int) []byte {
	t.Helper()
	m := answer(query())
	base, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	m.SetEdns0(4096, false)
	opt := m.IsEdns0()
	pad := &dns.EDNS0_PADDING{}
	opt.Option = append(opt.Option, pad)
	withZeroPad, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	overhead := len(withZeroPad) - len(base)
	need := size - len(base) - overhead
	if need < 0 {
		t.Fatalf("size %d too small for padding overhead %d", size, overhead)
	}
	pad.Padding = make([]byte, need)
	out, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != size {
		t.Fatalf("packed length = %d, want %d", len(out), size)
	}
	return out
}

// countingListener counts accepted connections, so a test can prove a second
// request was never attempted.
type countingListener struct {
	net.Listener
	n *int32
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		atomic.AddInt32(l.n, 1)
	}
	return c, err
}

func dohSpec(t *testing.T, srv *httptest.Server, pool *x509.CertPool) Spec {
	t.Helper()
	s, err := Parse(srv.URL + "/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	s.RootCAs = pool
	return s
}

func TestDoHRoundTrip(t *testing.T) {
	cert, pool := testCert(t)
	seen := new(dns.Msg)
	srv := dohServer(t, cert, dohEcho(t, seen))

	u, err := New(dohSpec(t, srv, pool), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !u.Secure() {
		t.Error("Secure() = false for DoH")
	}
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
}

// RFC 8484 section 4.1: the id is zero on the wire. The caller still gets its
// own id back, because the rest of KyDNS matches on it.
func TestDoHZeroesTheWireID(t *testing.T) {
	cert, pool := testCert(t)
	seen := new(dns.Msg)
	srv := dohServer(t, cert, dohEcho(t, seen))

	u, _ := New(dohSpec(t, srv, pool), 2*time.Second)
	req := query()
	req.Id = 4242
	resp, err := u.Exchange(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if seen.Id != 0 {
		t.Errorf("wire id = %d, want 0", seen.Id)
	}
	if resp.Id != 4242 {
		t.Errorf("response id = %d, want the caller's 4242", resp.Id)
	}
}

func TestDoHPostsTheRightHeaders(t *testing.T) {
	cert, pool := testCert(t)
	var method, contentType, accept string
	seen := new(dns.Msg)
	echo := dohEcho(t, seen)
	srv := dohServer(t, cert, func(w http.ResponseWriter, r *http.Request) {
		method, contentType, accept = r.Method, r.Header.Get("Content-Type"), r.Header.Get("Accept")
		echo(w, r)
	})

	u, _ := New(dohSpec(t, srv, pool), 2*time.Second)
	if _, err := u.Exchange(context.Background(), query()); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost {
		t.Errorf("method = %q, want POST", method)
	}
	if contentType != "application/dns-message" {
		t.Errorf("Content-Type = %q", contentType)
	}
	if accept != "application/dns-message" {
		t.Errorf("Accept = %q", accept)
	}
}

func TestDoHRejectsBadResponses(t *testing.T) {
	cert, pool := testCert(t)
	for name, tc := range map[string]struct {
		handler http.HandlerFunc
		want    string
	}{
		"non-200": {func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusInternalServerError)
		}, "500"},
		"wrong content type": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html>"))
		}, "content type"},
		"content type look-alike suffix": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/dns-message-evil")
			w.Write([]byte("nope"))
		}, "content type"},
		"oversized body": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(make([]byte, dns.MaxMsgSize+5000))
		}, "exceeds"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := dohServer(t, cert, tc.handler)
			u, _ := New(dohSpec(t, srv, pool), 2*time.Second)
			_, err := u.Exchange(context.Background(), query())
			if err == nil {
				t.Fatal("Exchange() error = nil")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestDoHRejectsUntrustedCertificate(t *testing.T) {
	cert, _ := testCert(t)
	seen := new(dns.Msg)
	srv := dohServer(t, cert, dohEcho(t, seen))

	u, _ := New(dohSpec(t, srv, x509.NewCertPool()), 2*time.Second)
	if _, err := u.Exchange(context.Background(), query()); err == nil {
		t.Fatal("Exchange() error = nil against an untrusted certificate")
	}
}

// The socket goes to the configured IP; only the URL and SNI carry the name.
func TestDoHDialsThePinnedAddress(t *testing.T) {
	cert, pool := testCert(t, "dns.example.test")
	seen := new(dns.Msg)
	echo := dohEcho(t, seen)
	var sni string
	srv := dohServer(t, cert, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			sni = r.TLS.ServerName
		}
		echo(w, r)
	})

	s, err := Parse(srv.URL + "/dns-query#dns.example.test")
	if err != nil {
		t.Fatal(err)
	}
	s.RootCAs = pool
	if !strings.Contains(s.URL, "dns.example.test") {
		t.Fatalf("URL = %q, want the server name", s.URL)
	}
	u, _ := New(s, 2*time.Second)
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
	// testCert also covers 127.0.0.1, the dialled address, so a handshake
	// that verified against the wrong name would still pass. Only the SNI
	// the server actually saw proves the configured name was used.
	if sni != "dns.example.test" {
		t.Errorf("SNI = %q, want %q", sni, "dns.example.test")
	}
}

func TestDoHAcceptsExactlyMaxMsgSize(t *testing.T) {
	cert, pool := testCert(t)
	wire := exactSizedWire(t, dns.MaxMsgSize)
	srv := dohServer(t, cert, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(wire)
	})

	u, _ := New(dohSpec(t, srv, pool), 2*time.Second)
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
}

func TestDoHAcceptsCaseInsensitiveContentType(t *testing.T) {
	cert, pool := testCert(t)
	// Not dohEcho: it sets its own lowercase Content-Type, which would mask
	// the case variant this test needs on the wire.
	srv := dohServer(t, cert, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		wire, err := answer(query()).Pack()
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "Application/DNS-Message")
		w.Write(wire)
	})

	u, _ := New(dohSpec(t, srv, pool), 2*time.Second)
	resp, err := u.Exchange(context.Background(), query())
	wantAnswer(t, resp, err)
}

// A malicious or misconfigured upstream cannot use a redirect to make the
// client resend the query body in cleartext.
func TestDoHDoesNotFollowRedirects(t *testing.T) {
	cert, pool := testCert(t)
	var handlerCalls int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&handlerCalls, 1)
		w.Header().Set("Location", "http://evil.invalid/elsewhere")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	var accepts int32
	srv.Listener = countingListener{srv.Listener, &accepts}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	u, _ := New(dohSpec(t, srv, pool), 2*time.Second)
	_, err := u.Exchange(context.Background(), query())
	if err == nil {
		t.Fatal("Exchange() error = nil for a redirect response")
	}
	if !strings.Contains(err.Error(), "307") {
		t.Errorf("error = %v, want it to mention the redirect status", err)
	}
	if got := atomic.LoadInt32(&handlerCalls); got != 1 {
		t.Errorf("handler calls = %d, want 1 (no redirect follow)", got)
	}
	if got := atomic.LoadInt32(&accepts); got != 1 {
		t.Errorf("accepted connections = %d, want 1 (the redirect target was never contacted)", got)
	}
}
